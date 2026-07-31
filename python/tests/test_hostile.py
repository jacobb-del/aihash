"""Враждебный ввод.

Верификатор по определению обрабатывает файл, полученный от противоположной
стороны. Он обязан выдавать вердикт, а не падать и не съедать память машины
проверяющего.
"""

import json
import zipfile

import pytest

from aihash import verify

GOOD = ["manifest.json", "records.jsonl", "proofs.json", "segment.json", "day.json"]


def make(path, entries, compress=zipfile.ZIP_STORED):
    with zipfile.ZipFile(path, "w", compress) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return str(path)


def test_zip_bomb_is_refused_without_unpacking(tmp_path):
    p = make(tmp_path / "bomb.seal",
             {**{n: "{}" for n in GOOD}, "manifest.json": b"{}" + b" " * (600 * 1024**2)},
             zipfile.ZIP_DEFLATED)
    r = verify.verify_bundle(p)
    assert r["status"] == verify.BROKEN
    assert "archive bomb" in " ".join(r["problems"])


def test_entry_name_escaping_the_archive_is_refused(tmp_path):
    p = make(tmp_path / "trav.seal",
             {**{n: "{}" for n in GOOD}, "anchors/../../../../etc/passwd": "x"})
    r = verify.verify_bundle(p)
    assert r["status"] == verify.BROKEN
    assert "escapes it" in " ".join(r["problems"])


def test_too_many_entries_is_refused(tmp_path):
    p = make(tmp_path / "many.seal",
             {**{n: "{}" for n in GOOD},
              **{"anchors/x%04d" % i: "x" for i in range(600)}})
    r = verify.verify_bundle(p)
    assert r["status"] == verify.BROKEN
    assert "entries, the limit" in " ".join(r["problems"])


@pytest.mark.parametrize("records,expect", [
    ('{"seq":"нет","ts":1,"fields":[]}', "is not a number"),
    ('{"ts":1,"fields":[]}', "is not a number"),
    ('{"seq":1,"ts":1}', "is not a list"),
    ("не json", "Expecting"),
    ("", "no disclosed records"),
])
def test_malformed_record_gives_a_verdict_not_a_traceback(tmp_path, records, expect):
    p = make(tmp_path / "bad.seal",
             {**{n: "{}" for n in GOOD}, "records.jsonl": records,
              "manifest.json": json.dumps({"format": "aihash/1", "hash": "sha256"})})
    r = verify.verify_bundle(p)
    assert r["status"] == verify.BROKEN
    assert expect in " ".join(r["problems"]), r["problems"]


def test_not_an_archive_gives_a_verdict(tmp_path):
    p = tmp_path / "junk.seal"
    p.write_bytes("это вообще не архив".encode("utf-8"))
    r = verify.verify_bundle(str(p))
    assert r["status"] == verify.BROKEN
    assert r["problems"]


def test_corrupt_journal_gives_a_verdict_not_a_traceback(tmp_path):
    root = tmp_path / "journal"
    (root / "days").mkdir(parents=True)
    (root / "streams").mkdir()
    (root / "realm.json").write_text(
        json.dumps({"format": "aihash/1", "hash": "sha256", "realm_id": "t"}))
    (root / "days" / "2026-01-01.day.json").write_text("{ это не json")
    r = verify.verify_journal(str(root))
    assert not r.ok
    assert "cannot be read" in " ".join(r.problems)


def test_stream_id_cannot_escape_its_directory():
    from aihash import core
    for bad in ["..", ".", "....", ".hidden"]:
        with pytest.raises(core.FormatError):
            core.check_id(bad, "stream_id")
