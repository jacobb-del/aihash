"""Экспортер OpenTelemetry.

Основной путь подключения. У целевой аудитории — разработчиков ИИ-агентов,
обеспокоенных воспроизводимостью, — наблюдаемость уже стоит, и почти вся она
построена на OTel. Экспортер означает, что «одна строка кода» это правда, а не
маркетинг, и что мы буквально работаем рядом с существующими системами, а не
вместо них.

    import aihash.otel
    log = aihash.otel.install("./journal", realm="romashka-prod")

Дальше приложение пишет трассировку как обычно; каждый завершённый span
становится записью в цепи.

opentelemetry-sdk — необязательная зависимость: pip install 'aihash[otel]'.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional

from . import core
from .journal import Journal

# Атрибуты ресурса, которые имеют доказательственный смысл: чья система, какой
# версии и в каком окружении отвечала. Остальное — шум в каждой записи.
RESOURCE_KEYS = ("service.name", "service.version", "service.instance.id",
                 "deployment.environment", "deployment.environment.name")

_OWN_FIELDS = frozenset((
    "span.name", "span.kind", "span.status", "span.status_message",
    "span.start_ms", "span.end_ms", "span.duration_ms", "span.events",
    "trace.id", "span.id", "span.parent_id",
    "exception.type", "exception.message", "exception.stacktrace"))


def _export_result(ok: bool):
    try:
        from opentelemetry.sdk.trace.export import SpanExportResult
    except ImportError:
        return ok
    return SpanExportResult.SUCCESS if ok else SpanExportResult.FAILURE


def sanitize_stream_id(value: str, fallback: str = "otel") -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
    out = "".join(c if c in allowed else "-" for c in value).strip("-")
    return (out[:64] or fallback)


def attr_value(v: Any) -> Any:
    """Значение атрибута OTel в то, что принимает запись: строка или байты.

    Преобразование одностороннее и это нормально: запись хранит то, что видел
    человек, а не типизированный объект. Списки укладываются в JSON, чтобы не
    терять порядок.
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return repr(v) if isinstance(v, float) else str(v)
    if isinstance(v, (list, tuple)):
        return json.dumps([attr_value(x) if not isinstance(x, (bytes, bytearray))
                           else x.hex() for x in v], ensure_ascii=False)
    return str(v)


def attr_name(key: str) -> str:
    """Имена, начинающиеся с _, зарезервированы форматом; чужие атрибуты
    туда попадать не должны. Столкновения с нашими полями тоже разводим —
    подмена span.name атрибутом сделала бы запись недостоверной."""
    if key.startswith("_") or key in _OWN_FIELDS:
        key = "attr." + key.lstrip("_")
    return key[:255]


def span_to_fields(span) -> Dict[str, Any]:
    ctx = span.get_span_context()
    start_ms = (span.start_time or 0) // 1_000_000
    end_ms = (span.end_time or span.start_time or 0) // 1_000_000

    fields: Dict[str, Any] = {
        "span.name": span.name or "",
        "span.kind": str(getattr(span, "kind", "")).rsplit(".", 1)[-1],
        "trace.id": format(ctx.trace_id, "032x"),
        "span.id": format(ctx.span_id, "016x"),
        "span.start_ms": str(start_ms),
        "span.end_ms": str(end_ms),
        "span.duration_ms": str(max(0, end_ms - start_ms)),
    }
    parent = getattr(span, "parent", None)
    if parent is not None:
        fields["span.parent_id"] = format(parent.span_id, "016x")

    status = getattr(span, "status", None)
    if status is not None:
        fields["span.status"] = str(getattr(status, "status_code", "")).rsplit(".", 1)[-1]
        if getattr(status, "description", None):
            fields["span.status_message"] = status.description

    resource = getattr(span, "resource", None)
    if resource is not None:
        for k in RESOURCE_KEYS:
            v = resource.attributes.get(k)
            if v is not None:
                fields[k] = attr_value(v)

    for k, v in (span.attributes or {}).items():
        fields[attr_name(k)] = attr_value(v)

    events = list(getattr(span, "events", None) or [])
    if events:
        fields["span.events"] = str(len(events))
        for e in events:
            if e.name != "exception":
                continue
            a = e.attributes or {}
            for src, dst in (("exception.type", "exception.type"),
                             ("exception.message", "exception.message"),
                             ("exception.stacktrace", "exception.stacktrace")):
                if a.get(src) is not None:
                    fields[dst] = attr_value(a[src])
            break

    return fields


class AihashSpanExporter:
    """Экспортер спанов в журнал. Один завершённый span — одна запись.

    Пишет асинхронно: горячий путь приложения блокировать нельзя. Переполнение
    очереди журнала даёт ошибку, а не тихий сброс, поэтому OTel получит отказ и
    повторит — потерять событие молча доказательственный журнал не вправе.
    """

    def __init__(self, journal: Journal, stream: Optional[str] = None,
                 stream_from_service: bool = True, own_journal: bool = False):
        self.journal = journal
        self.stream = stream
        self.stream_from_service = stream_from_service
        self.own_journal = own_journal
        self._shutdown = False

    def _stream_for(self, span) -> str:
        if self.stream:
            return self.stream
        if self.stream_from_service:
            resource = getattr(span, "resource", None)
            if resource is not None:
                name = resource.attributes.get("service.name")
                if name:
                    return sanitize_stream_id(str(name))
        return "otel"

    def export(self, spans: Iterable):
        if self._shutdown:
            return _export_result(False)
        try:
            for span in spans:
                fields = span_to_fields(span)
                ts = (span.end_time or span.start_time or 0) // 1_000_000
                self.journal.stream(self._stream_for(span)).record(
                    fields, ts=ts or None)
        except core.FormatError:
            raise
        except Exception:
            return _export_result(False)
        return _export_result(True)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        try:
            self.journal.flush(timeout_millis / 1000.0)
            return True
        except Exception:
            return False

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        if self.own_journal:
            self.journal.close()
        else:
            self.journal.flush()


def install(root: str, *, realm: str, stream: Optional[str] = None,
            tracer_provider=None, journal: Optional[Journal] = None,
            **journal_kw) -> Journal:
    """Подключить экспортер к провайдеру трассировки. Возвращает журнал.

    Если провайдер не передан, берётся текущий глобальный. Существующие
    экспортеры не трогаются: мы работаем рядом с наблюдаемостью, а не вместо.
    """
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        raise core.FormatError(
            "нужен opentelemetry-sdk: pip install 'aihash[otel]'") from e

    own = journal is None
    j = journal or Journal(root, realm, **journal_kw)
    provider = tracer_provider or trace.get_tracer_provider()
    if not hasattr(provider, "add_span_processor"):
        if own:
            j.close()
        raise core.FormatError(
            "текущий провайдер трассировки не принимает обработчики — "
            "настройте opentelemetry.sdk.trace.TracerProvider до вызова install()")
    provider.add_span_processor(
        BatchSpanProcessor(AihashSpanExporter(j, stream=stream, own_journal=own)))
    return j
