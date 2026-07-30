"""Экспортер OpenTelemetry: спан становится записью в цепи.

Проверяется не «код не падает», а то, что из настоящей трассировки получается
журнал, который сходится и из которого собирается пакет доказательства.
"""


import pytest

pytest.importorskip("opentelemetry.sdk", reason="нужен opentelemetry-sdk")

from opentelemetry.sdk.resources import Resource  # noqa: E402
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402

from aihash import bundle, journal, otel, seal, store, verify  # noqa: E402

REALM = "romashka-prod"


def make_provider(root, clock=None, stream=None):
    j = journal.Journal(root, REALM, beacon_source=None, clock=clock)
    provider = TracerProvider(resource=Resource.create({
        "service.name": "voice-eu-3", "service.version": "14.2",
        "deployment.environment": "prod"}))
    provider.add_span_processor(
        SimpleSpanProcessor(otel.AihashSpanExporter(j, stream=stream)))
    return provider, j


def fields_of(rec):
    return {f["name"]: f.get("s") for f in rec["fields"]}


def read_all(root):
    layout = store.Layout(root)
    out = []
    for s in layout.streams():
        for p in layout.periods(s):
            out.extend(layout.read_segment(s, p))
    return out


def test_span_becomes_a_record(tmp_path):
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("llm.chat") as span:
        span.set_attribute("gen_ai.system", "openai")
        span.set_attribute("gen_ai.request.model", "gpt-4o-2026-02-11")
        span.set_attribute("gen_ai.completion", "возврат придёт в течение 5 дней")
        span.set_attribute("gen_ai.usage.output_tokens", 12)
        span.set_attribute("stream", True)
    provider.shutdown()
    j.close()

    recs = read_all(root)
    assert len(recs) == 1
    f = fields_of(recs[0])
    assert f["span.name"] == "llm.chat"
    assert f["gen_ai.completion"] == "возврат придёт в течение 5 дней"
    assert f["gen_ai.usage.output_tokens"] == "12"
    assert f["stream"] == "true", "булево должно стать читаемым словом"
    assert f["service.name"] == "voice-eu-3"
    assert f["deployment.environment"] == "prod"
    assert len(f["trace.id"]) == 32 and len(f["span.id"]) == 16
    assert int(f["span.duration_ms"]) >= 0

    r = verify.verify_journal(root)
    assert r.ok, r.problems


def test_stream_comes_from_service_name(tmp_path):
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    provider.get_tracer("t").start_span("x").end()
    provider.shutdown()
    j.close()
    assert store.Layout(root).streams() == ["voice-eu-3"]


def test_nested_spans_keep_parent(tmp_path):
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("handle_call"):
        with tracer.start_as_current_span("llm.chat"):
            pass
    provider.shutdown()
    j.close()

    recs = {fields_of(r)["span.name"]: fields_of(r) for r in read_all(root)}
    assert recs["llm.chat"]["span.parent_id"] == recs["handle_call"]["span.id"]
    assert recs["llm.chat"]["trace.id"] == recs["handle_call"]["trace.id"]
    assert "span.parent_id" not in recs["handle_call"]


def test_exception_is_recorded(tmp_path):
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    tracer = provider.get_tracer("t")
    with pytest.raises(ValueError):
        with tracer.start_as_current_span("tool.call"):
            raise ValueError("биллинг недоступен")
    provider.shutdown()
    j.close()

    f = fields_of(read_all(root)[0])
    assert f["exception.type"] == "ValueError"
    assert f["exception.message"] == "биллинг недоступен"
    assert f["span.status"] == "ERROR"


def test_reserved_and_colliding_names_are_moved_aside(tmp_path):
    """Атрибут не вправе подменить наши поля или влезть в зарезервированные
    имена: и то и другое сделало бы запись недостоверной."""
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    with provider.get_tracer("t").start_as_current_span("x") as span:
        span.set_attribute("_beacon.round", "подделка")
        span.set_attribute("span.name", "подделка")
        span.set_attribute("trace.id", "подделка")
    provider.shutdown()
    j.close()

    f = fields_of(read_all(root)[0])
    assert f["span.name"] == "x"
    assert f["attr.span.name"] == "подделка"
    assert f["attr.beacon.round"] == "подделка"
    assert f["attr.trace.id"] == "подделка"
    assert not any(k.startswith("_") for k in f)


def test_sequences_keep_order(tmp_path):
    root = str(tmp_path / "journal")
    provider, j = make_provider(root)
    with provider.get_tracer("t").start_as_current_span("x") as span:
        span.set_attribute("tools", ["orders.get", "billing.refund"])
    provider.shutdown()
    j.close()
    assert fields_of(read_all(root)[0])["tools"] == '["orders.get", "billing.refund"]'


def test_end_to_end_from_otel_to_sealed_bundle(tmp_path):
    """Трассировка -> журнал -> пломба -> пакет доказательства."""
    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 86400_000
    provider, j = make_provider(root, clock=lambda: fixed)
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("handle_call"):
        with tracer.start_as_current_span("llm.chat") as span:
            span.set_attribute("gen_ai.completion", "возврат придёт в течение 5 дней")
    provider.shutdown()
    j.close()

    layout = store.Layout(root)
    date = journal.period_of(fixed)
    seal.seal_day(layout, REALM, date)
    seal.anchor_day(layout, date, ["feed"])

    target = [r["seq"] for r in read_all(root)
              if fields_of(r)["span.name"] == "llm.chat"][0]
    out = str(tmp_path / "ep.seal")
    bundle.build(root, "voice-eu-3", [target], out)

    res = verify.verify_bundle(out)
    assert res["status"] == verify.SEALED, res["problems"]
    assert res["manifest"]["stream_id"] == "voice-eu-3"


def test_install_wires_into_a_provider(tmp_path):
    root = str(tmp_path / "journal")
    provider = TracerProvider(resource=Resource.create({"service.name": "svc"}))
    otel.install(root, realm=REALM, stream="app", tracer_provider=provider,
                 beacon_source=None)
    provider.get_tracer("t").start_span("x").end()
    provider.force_flush()
    provider.shutdown()
    assert store.Layout(root).streams() == ["app"]
    assert verify.verify_journal(root).ok


def test_service_name_is_sanitised_for_a_stream_id():
    assert otel.sanitize_stream_id("My Service / v2") == "My-Service---v2"
    assert otel.sanitize_stream_id("") == "otel"
    assert len(otel.sanitize_stream_id("x" * 200)) == 64
