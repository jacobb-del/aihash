"""Закрытие отрезков, суточная отметка, постановка пломбы."""

from __future__ import annotations

import os
import time
from typing import List, Optional

from . import anchors as anchors_mod
from . import core, store


def _prev_segment_ckpt(layout: store.Layout, stream_id: str, period: str) -> bytes:
    earlier = [p for p in layout.periods(stream_id) if p < period]
    for p in reversed(earlier):
        ck = layout.read_segment_ckpt(stream_id, p)
        if ck:
            return bytes.fromhex(ck["checkpoint"])
    return core.ZERO32


def _link_before(layout: store.Layout, stream_id: str, period: str) -> bytes:
    """Звено, предшествующее отрезку.

    Берётся из отметки предыдущего отрезка, а не перечитыванием его записей:
    отметка уже запечатана, и доверять ей ровно столько же, сколько цепи.
    """
    earlier = [p for p in layout.periods(stream_id) if p < period]
    for p in reversed(earlier):
        ck = layout.read_segment_ckpt(stream_id, p)
        if ck:
            return bytes.fromhex(ck["link_last"])
        tip = layout.read_segment_tail(stream_id, p)
        if tip:
            return bytes.fromhex(tip["link"])
    return core.genesis(stream_id)


def _guard_current(period: str, allow_open: bool) -> None:
    """Запечатанный отрезок закрыт для дописывания навсегда, поэтому закрывать
    можно только завершившиеся сутки. Иначе первая же запись после пломбы
    порвала бы отметку отрезка."""
    if allow_open:
        return
    if period >= time.strftime("%Y-%m-%d", time.gmtime()):
        raise core.FormatError(
            "сутки %s ещё идут — закрывать можно только завершившиеся; "
            "запечатанный отрезок больше не принимает записи" % period)


def segment_links(layout: store.Layout, stream_id: str, period: str,
                  recs: List[dict], start: bytes) -> List[bytes]:
    """Пересчитать звенья ОТРЕЗКА, а не всего журнала.

    Начало берётся из отметки предыдущего отрезка. Пересчёт от начала времён
    давал бы то же самое, но стоил бы чтения всего журнала на каждое закрытие
    суток и на каждую сборку пакета.
    """
    links = []
    prev = start
    for rec in recs:
        croot = core.content_root(store.fields_for_root(rec["fields"]))
        if croot.hex() != rec["content_root"]:
            raise core.FormatError(
                "%s %s seq=%d: содержимое не совпадает с записанным отпечатком"
                % (stream_id, period, rec["seq"]))
        prev = core.link(prev, rec["seq"], croot, rec["ts"])
        if prev.hex() != rec["link"]:
            raise core.FormatError(
                "%s %s seq=%d: звено не совпадает с записанным"
                % (stream_id, period, rec["seq"]))
        links.append(prev)
    return links


def seal_segment(layout: store.Layout, stream_id: str, period: str,
                 allow_open: bool = False) -> Optional[dict]:
    """Закрыть отрезок. Возвращает отметку или None, если записей нет."""
    _guard_current(period, allow_open)
    recs = layout.read_segment(stream_id, period)
    if not recs:
        return None

    lb = _link_before(layout, stream_id, period)
    links = segment_links(layout, stream_id, period, recs, lb)

    first_seq, last_seq = recs[0]["seq"], recs[-1]["seq"]
    root = core.seg_root(links)
    prev_ckpt = _prev_segment_ckpt(layout, stream_id, period)
    ck = core.seg_ckpt(stream_id, period, first_seq, last_seq, len(recs),
                       lb, links[-1], root, prev_ckpt)
    obj = {"format": core.FORMAT_VERSION, "stream_id": stream_id,
           "period_id": period, "first_seq": first_seq, "last_seq": last_seq,
           "count": len(recs), "link_before": lb.hex(),
           "link_last": links[-1].hex(), "segment_root": root.hex(),
           "prev_checkpoint": prev_ckpt.hex(), "checkpoint": ck.hex()}
    store.write_json(layout.segment_ckpt_file(stream_id, period), obj)
    return obj


def _prev_day_ckpt(layout: store.Layout, date: str) -> bytes:
    for d in reversed([x for x in layout.dates() if x < date]):
        day = layout.read_day(d)
        if day:
            return bytes.fromhex(day["day_checkpoint"])
    return core.ZERO32


def seal_day(layout: store.Layout, realm_id: str, date: str,
             allow_open: bool = False) -> Optional[dict]:
    """Закрыть сутки по всем потокам. Возвращает суточную отметку."""
    _guard_current(date, allow_open)
    ckpts, streams = [], []
    for stream_id in layout.streams():
        if date not in layout.periods(stream_id):
            continue
        seg = layout.read_segment_ckpt(stream_id, date) or \
            seal_segment(layout, stream_id, date, allow_open=True)
        if seg is None:
            continue
        streams.append(stream_id)
        ckpts.append(bytes.fromhex(seg["checkpoint"]))
    if not ckpts:
        return None

    order = sorted(range(len(streams)), key=lambda i: streams[i].encode("utf-8"))
    streams = [streams[i] for i in order]
    ckpts = [ckpts[i] for i in order]

    root = core.day_root(ckpts)
    prev = _prev_day_ckpt(layout, date)
    ck = core.day_ckpt(realm_id, date, len(ckpts), root, prev)
    obj = {"format": core.FORMAT_VERSION, "realm_id": realm_id, "date": date,
           "streams": streams, "segment_checkpoints": [c.hex() for c in ckpts],
           "day_root": root.hex(), "prev_checkpoint": prev.hex(),
           "day_checkpoint": ck.hex()}
    os.makedirs(os.path.dirname(layout.day_file(date)), exist_ok=True)
    store.write_json(layout.day_file(date), obj)
    return obj


def anchor_day(layout: store.Layout, date: str, kinds: List[str],
               config: Optional[dict] = None) -> List[dict]:
    """Поставить пломбы на суточную отметку.

    Пломба считается поставленной при успехе хотя бы одного типа. Отказ одного
    типа не отменяет остальные — их отказы не коррелируют, ради этого их и три.
    """
    day = layout.read_day(date)
    if day is None:
        raise core.FormatError("сутки %s не закрыты — нечего пломбировать" % date)
    target = bytes.fromhex(day["day_checkpoint"])
    results = []
    for kind in kinds:
        try:
            res = anchors_mod.stamp(kind, target, layout, date, config or {})
            results.append({"type": kind, "ok": True, **res})
        except Exception as e:  # noqa: BLE001 — отказ одного типа не фатален
            results.append({"type": kind, "ok": False, "error": str(e)})
    return results
