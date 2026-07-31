"""Проверка журнала и пакета доказательства.

Сеть не используется. Наши серверы не используются. Если для проверки нужны
мы — доказательство обесценивается вдвое, оппонент скажет «проверено
инфраструктурой ответчика».

Состояний не два:
  SEALED      — сходится и запечатано
  UNVERIFIED  — сходится, пломба стоит и относится к этой отметке, но
                подтвердить её здесь нечем (нет сертификата службы штампов,
                нет клиента opentimestamps)
  OPEN        — сходится, но пломбы ещё нет (обычное состояние первых суток)
  BROKEN      — не сходится

UNVERIFIED и OPEN путать нельзя. Сказать «не запечатано» там, где пломба
стоит, — недоговорка того же сорта, что и ложное обвинение: получатель решит,
что журнал не запечатан, и недооценит доказательство.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import zipfile
from typing import Dict, List, Optional

from . import anchors as anchors_mod
from . import beacon as beacon_mod
from . import core, store

SEALED = "sealed"
UNVERIFIED = "unverified"
OPEN = "open"
BROKEN = "broken"

# Верификатор по определению обрабатывает файл, полученный от противоположной
# стороны. Пределы не про удобство: без них присланный архив кладёт машину
# проверяющего, а разбор без проверки структуры валит его трассировкой вместо
# вердикта. Законный пакет на порядки меньше любого из этих чисел.
MAX_ENTRIES = 512
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024


class BundleError(core.FormatError):
    """Пакет не удалось прочитать. Это вердикт, а не сбой верификатора."""


def _safe_name(name: str) -> str:
    if name.startswith("/") or name.startswith("\\") or ":" in name.split("/")[0][1:]:
        raise BundleError("illegal name in the archive: %r" % name)
    parts = name.replace("\\", "/").split("/")
    if any(p in ("..", ".") for p in parts):
        raise BundleError("a name in the archive escapes it: %r" % name)
    return name


def read_bundle(path: str) -> Dict[str, bytes]:
    """Прочитать пакет с пределами на размер и количество."""
    files: Dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES:
            raise BundleError("the archive has %d entries, the limit is %d"
                              % (len(infos), MAX_ENTRIES))
        for info in infos:
            if info.is_dir():
                continue
            name = _safe_name(info.filename)
            if info.file_size > MAX_ENTRY_BYTES:
                raise BundleError(
                    "%s: declares %d bytes, the limit is %d — archive bomb"
                    % (name, info.file_size, MAX_ENTRY_BYTES))
            with z.open(info) as fh:
                data = fh.read(MAX_ENTRY_BYTES + 1)
            if len(data) > MAX_ENTRY_BYTES:
                raise BundleError("%s: the uncompressed size exceeds the limit" % name)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise BundleError("the total archive size exceeds %d bytes"
                                  % MAX_TOTAL_BYTES)
            files[name] = data
    return files


def _need_int(obj: dict, key: str, where: str) -> int:
    v = obj.get(key)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise BundleError("%s: field %r is missing or is not a number"
                          % (where, key))
    return v


def _need_list(obj: dict, key: str, where: str) -> list:
    v = obj.get(key)
    if not isinstance(v, list):
        raise BundleError("%s: field %r is missing or is not a list"
                          % (where, key))
    return v


class Result:
    def __init__(self):
        self.problems: List[str] = []
        self.streams: List[dict] = []
        self.days: List[dict] = []
        self.records = 0
        self.realm: Optional[dict] = None

    @property
    def status(self) -> str:
        if self.problems:
            return BROKEN
        if any(d["status"] == SEALED for d in self.days):
            return SEALED
        if any(d["status"] == UNVERIFIED for d in self.days):
            return UNVERIFIED
        return OPEN

    @property
    def ok(self) -> bool:
        return not self.problems

    def fail(self, msg: str) -> None:
        self.problems.append(msg)

    def to_dict(self) -> dict:
        return {"status": self.status, "ok": self.ok, "records": self.records,
                "realm": self.realm, "streams": self.streams, "days": self.days,
                "problems": self.problems}


def verify_journal(root: str, config: Optional[dict] = None) -> Result:
    """Проверить журнал. Повреждённый или враждебный файл обязан давать вердикт,
    а не трассировку: верификатором пользуется человек, а не разработчик."""
    r = Result()
    try:
        return _verify_journal(root, config or {})
    except (core.FormatError, json.JSONDecodeError, UnicodeDecodeError,
            KeyError, TypeError, ValueError) as e:
        r.fail("the journal cannot be read: %s" % e)
        return r
    except OSError as e:
        r.fail("the journal is unavailable: %s" % e)
        return r


def _verify_journal(root: str, config: dict) -> Result:
    layout = store.Layout(root)
    r = Result()

    if not os.path.exists(layout.realm_file):
        r.fail("no realm.json — this directory is not an aihash journal")
        return r
    realm = layout.realm()
    r.realm = realm
    if realm.get("format") != core.FORMAT_VERSION:
        r.fail("format version %r is not supported by this verifier"
               % realm.get("format"))
        return r
    if realm.get("hash") != core.HASH_NAME:
        r.fail("hash function %r is not supported" % realm.get("hash"))
        return r

    for stream_id in layout.streams():
        # Звенья нужны только внутри проверки потока: удерживать их здесь
        # значило бы держать в памяти весь журнал без всякой пользы.
        _verify_stream(layout, stream_id, r)

    for date in layout.dates():
        _verify_day(layout, realm["realm_id"], date, r, config)

    _report_unsealed(layout, r)
    return r


def _verify_stream(layout: store.Layout, stream_id: str, r: Result) -> Dict[int, bytes]:
    links: Dict[int, bytes] = {}
    prev = core.genesis(stream_id)
    expect = 1
    info = {"stream_id": stream_id, "periods": [], "records": 0, "redacted": 0}

    for period in layout.periods(stream_id):
        recs = layout.read_segment(stream_id, period)
        link_before = prev
        for rec in recs:
            seq = rec["seq"]
            if seq != expect:
                r.fail("stream %s, segment %s: expected seq %d, found %d — "
                       "gap in the chain" % (stream_id, period, expect, seq))
                return links
            try:
                fields = store.fields_for_root(rec["fields"])
                croot = core.content_root(fields)
            except core.FormatError as e:
                r.fail("stream %s seq=%d: %s" % (stream_id, seq, e))
                return links
            prev = core.link(prev, seq, croot, rec["ts"])
            if prev.hex() != rec.get("link"):
                r.fail("stream %s seq=%d: the link does not match the recorded one"
                       % (stream_id, seq))
                return links
            links[seq] = prev
            expect += 1
            info["records"] += 1
            info["redacted"] += sum(1 for f in rec["fields"] if "leaf" in f)

        ck = layout.read_segment_ckpt(stream_id, period)
        state = {"period": period, "count": len(recs), "sealed": ck is not None}
        if ck is not None and recs:
            seg_links = [links[q] for q in range(recs[0]["seq"], recs[-1]["seq"] + 1)]
            root = core.seg_root(seg_links)
            want = core.seg_ckpt(stream_id, period, ck["first_seq"], ck["last_seq"],
                                 ck["count"], bytes.fromhex(ck["link_before"]),
                                 bytes.fromhex(ck["link_last"]), root,
                                 bytes.fromhex(ck["prev_checkpoint"]))
            if root.hex() != ck["segment_root"]:
                r.fail("stream %s, segment %s: the segment root does not match"
                       % (stream_id, period))
            elif ck["link_before"] != link_before.hex():
                r.fail("stream %s, segment %s: not linked to the previous segment"
                       % (stream_id, period))
            elif want.hex() != ck["checkpoint"]:
                r.fail("stream %s, segment %s: the segment checkpoint does not match"
                       % (stream_id, period))
        info["periods"].append(state)

    r.records += info["records"]
    r.streams.append(info)
    return links


def _verify_day(layout: store.Layout, realm_id: str, date: str, r: Result,
                config: dict) -> None:
    day = layout.read_day(date)
    entry = {"date": date, "status": OPEN, "anchors": [], "streams": day["streams"]}

    ckpts = []
    for stream_id in day["streams"]:
        ck = layout.read_segment_ckpt(stream_id, date)
        if ck is None:
            r.fail("day %s: no segment checkpoint for stream %s" % (date, stream_id))
            entry["status"] = BROKEN
            r.days.append(entry)
            return
        ckpts.append(bytes.fromhex(ck["checkpoint"]))

    if [c.hex() for c in ckpts] != day["segment_checkpoints"]:
        r.fail("day %s: the list of segment checkpoints does not match" % date)
        entry["status"] = BROKEN
        r.days.append(entry)
        return
    if day["streams"] != sorted(day["streams"]):
        r.fail("day %s: streams are not sorted by stream_id" % date)

    root = core.day_root(ckpts)
    want = core.day_ckpt(realm_id, date, len(ckpts), root,
                         bytes.fromhex(day["prev_checkpoint"]))
    if root.hex() != day["day_root"] or want.hex() != day["day_checkpoint"]:
        r.fail("day %s: the daily checkpoint does not match" % date)
        entry["status"] = BROKEN
        r.days.append(entry)
        return

    prev_expected = core.ZERO32
    for d in [x for x in layout.dates() if x < date]:
        prior = layout.read_day(d)
        if prior:
            prev_expected = bytes.fromhex(prior["day_checkpoint"])
    if day["prev_checkpoint"] != prev_expected.hex():
        r.fail("day %s: not linked to the previous day" % date)

    target = bytes.fromhex(day["day_checkpoint"])
    for path in layout.anchors_for(date) + _feed_paths(layout, config):
        res = anchors_mod.verify_file(path, target, config, date=date)
        entry["anchors"].append(res)
        if res["status"] == anchors_mod.FAILED:
            r.fail("day %s: seal %s does not match — %s"
                   % (date, res["type"], res.get("detail", "")))
    entry["status"] = _day_status(entry["anchors"])
    r.days.append(entry)


def _day_status(anchor_results: List[dict]) -> str:
    """Три исхода, а не два.

    Граница между «пломбы нет» и «пломба не подтверждена» проходит по тому,
    поставлена ли пломба вообще, а не по тому, удалось ли её проверить. Лента,
    в которой этих суток нет, — это «пломбы нет»; штамп без сертификата службы
    — это «пломба стоит, подпись не сверена».
    """
    if any(a["status"] == anchors_mod.OK for a in anchor_results):
        return SEALED
    if any(a["status"] == anchors_mod.UNVERIFIED and a.get("placed")
           for a in anchor_results):
        return UNVERIFIED
    return OPEN


def _feed_paths(layout: store.Layout, config: dict) -> List[str]:
    paths = []
    for p in [config.get("feed_path"),
              os.path.join(layout.anchors_dir(), "feed.jsonl")]:
        if p and os.path.exists(p) and p not in paths:
            paths.append(p)
    return paths


def _report_unsealed(layout: store.Layout, r: Result) -> None:
    sealed_dates = {d["date"] for d in r.days}
    for s in r.streams:
        for p in s["periods"]:
            if p["period"] not in sealed_dates and p["count"]:
                r.days.append({"date": p["period"], "status": OPEN, "anchors": [],
                               "streams": [s["stream_id"]],
                               "note": "the day is not closed — there is no seal yet"})


# --- пакет доказательства ---------------------------------------------------


def verify_bundle(path: str, config: Optional[dict] = None) -> dict:
    """Проверка одного пакета .seal. Ровно то, что делает оппонент у себя."""
    config = config or {}
    out = {"status": BROKEN, "problems": [], "checks": [], "path": path}

    def check(label: str, ok: bool, detail: str = "") -> bool:
        out["checks"].append({"label": label, "ok": ok, "detail": detail})
        if not ok:
            out["problems"].append(label + (": " + detail if detail else ""))
        return ok

    try:
        files = read_bundle(path)
    except (BundleError, zipfile.BadZipFile, OSError) as e:
        out["problems"].append(str(e))
        return out

    try:
        names = set(files)
        for req in ("manifest.json", "records.jsonl", "proofs.json",
                    "segment.json", "day.json"):
            if req not in names:
                out["problems"].append("the bundle has no %s" % req)
                return out

        def obj(name):
            v = json.loads(files[name].decode("utf-8"))
            if not isinstance(v, dict):
                raise BundleError("%s: an object was expected" % name)
            return v

        manifest = obj("manifest.json")
        proofs = obj("proofs.json")
        segment = obj("segment.json")
        day = obj("day.json")
        records = []
        for n, line in enumerate(files["records.jsonl"].decode("utf-8").splitlines(), 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            if not isinstance(rec, dict):
                raise BundleError("records.jsonl line %d: an object was expected" % n)
            _need_int(rec, "seq", "records.jsonl line %d" % n)
            _need_int(rec, "ts", "records.jsonl line %d" % n)
            _need_list(rec, "fields", "records.jsonl line %d" % n)
            records.append(rec)
        if not records:
            raise BundleError("the bundle has no disclosed records")
        if not isinstance(proofs.get("records"), dict):
            raise BundleError("proofs.json: no records section")
        anchor_blobs = {n: files[n] for n in names if n.startswith("anchors/")}
        bundled_ca = files.get("certs/rfc3161-ca.pem")
    except (BundleError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        out["problems"].append(str(e))
        return out

    if not check("format version", manifest.get("format") == core.FORMAT_VERSION,
                 str(manifest.get("format"))):
        return out

    for rec in records:
        seq = rec["seq"]
        p = proofs["records"][str(seq)]
        try:
            croot = core.content_root(store.fields_for_root(rec["fields"]))
        except core.FormatError as e:
            check("record seq=%d: fields" % seq, False, str(e))
            return out
        link = core.link(bytes.fromhex(p["prev_link"]), seq, croot, rec["ts"])
        if not check("record seq=%d: content and link" % seq,
                     link.hex() == p["link"]):
            return out
        leaf = core.seg_leaf(link)
        got = core.apply_path(leaf, [(s["side"], bytes.fromhex(s["h"]))
                                     for s in p["segment_path"]])
        if not check("record seq=%d: path to the segment root" % seq,
                     got.hex() == segment["segment_root"]):
            return out

    ck = core.seg_ckpt(segment["stream_id"], segment["period_id"],
                       segment["first_seq"], segment["last_seq"], segment["count"],
                       bytes.fromhex(segment["link_before"]),
                       bytes.fromhex(segment["link_last"]),
                       bytes.fromhex(segment["segment_root"]),
                       bytes.fromhex(segment["prev_checkpoint"]))
    if not check("segment checkpoint", ck.hex() == segment["checkpoint"]):
        return out

    got = core.apply_path(core.day_leaf(ck),
                          [(s["side"], bytes.fromhex(s["h"]))
                           for s in proofs["day_path"]])
    if not check("path to the daily root", got.hex() == day["day_root"]):
        return out

    dck = core.day_ckpt(day["realm_id"], day["date"], len(day["streams"]),
                        bytes.fromhex(day["day_root"]),
                        bytes.fromhex(day["prev_checkpoint"]))
    if not check("daily checkpoint", dck.hex() == day["day_checkpoint"]):
        return out

    target = dck
    anchor_results = []
    # Временный каталог создаётся системой, а не рядом с пакетом: каталог с
    # пакетом может быть доступен только на чтение, а мусор рядом с
    # доказательством выглядит подозрительно.
    tmpdir = tempfile.mkdtemp(prefix="aihash-verify-")
    # Сертификат из пакета в построении доверия не участвует. Он приехал вместе
    # с уликой: подделыватель, приложивший свой корень к своему штампу, заверил
    # бы сам себя. Передаётся дальше только как подсказка, какой корень искать,
    # — под именем, которое не даёт спутать его с доверенным.
    cfg = dict(config)
    if bundled_ca is not None:
        cfg["presented_ca"] = bundled_ca
    try:
        for name, blob in sorted(anchor_blobs.items()):
            tmp = os.path.join(tmpdir, os.path.basename(name))
            with open(tmp, "wb") as f:
                f.write(blob)
            res = anchors_mod.verify_file(tmp, target, cfg,
                                          date=day.get("date"))
            res["path"] = name
            anchor_results.append(res)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    if bundled_ca is not None:
        out["presented_ca_sha256"] = hashlib.sha256(bundled_ca).hexdigest()
    out["anchors"] = anchor_results
    for res in anchor_results:
        if res["status"] == anchors_mod.FAILED:
            check("seal %s" % res["type"], False, res.get("detail", ""))
    if out["problems"]:
        return out

    out["bounds"] = _bounds(records, anchor_results, manifest)
    out["status"] = _day_status(anchor_results)
    out["manifest"] = manifest
    out["records"] = records
    out["segment"] = segment
    out["day"] = day
    return out


def _bounds(records: List[dict], anchor_results: List[dict],
            manifest: dict) -> dict:
    lower, lower_src = None, None
    b = manifest.get("beacon")
    if b:
        lower = beacon_mod.lower_bound_ms(int(b["round"]), b["source"])
        lower_src = "%s раунд %s" % (b["source"], b["round"])
    upper, upper_src = None, None
    for a in anchor_results:
        if a["status"] == anchors_mod.OK and a.get("time"):
            upper, upper_src = a["time"], a["type"]
            break
    return {"lower_ms": lower, "lower_source": lower_src,
            "upper": upper, "upper_source": upper_src}
