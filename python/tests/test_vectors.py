"""Библиотека обязана сходиться с векторами этапа 0 побайтово.

Это главный тест проекта. Если он падает, реализация несовместима со
спецификацией, и всё остальное значения не имеет.
"""

import base64
import json
import os

import pytest

from aihash import core

V = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "..", "spec", "vectors")


def load(name):
    with open(os.path.join(V, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def raw_value(f):
    assert not ("s" in f and "b" in f), "s и b одновременно"
    return f["s"].encode("utf-8") if "s" in f else base64.b64decode(f["b"])


def fields_for_root(fields):
    out = []
    for f in fields:
        if "leaf" in f:
            out.append({"name": f["name"], "leaf": bytes.fromhex(f["leaf"])})
        else:
            out.append({"name": f["name"], "salt": bytes.fromhex(f["salt"]),
                        "value": raw_value(f)})
    return out


def test_varint():
    for c in load("01-varint")["cases"]:
        assert core.varint(c["value"]).hex() == c["hex"], c


def test_field_leaf():
    for c in load("02-field-leaf")["cases"]:
        got = core.field_leaf(c["name"], bytes.fromhex(c["salt"]), raw_value(c))
        assert got.hex() == c["leaf"], c["name"]


def test_merkle_and_paths():
    for c in load("03-merkle")["cases"]:
        leaves = [bytes.fromhex(x) for x in c["leaves"]]
        assert core.mth(leaves).hex() == c["root"], c["n"]
        for ap in c["audit_paths"]:
            path = [(s["side"], bytes.fromhex(s["h"])) for s in ap["path"]]
            assert core.apply_path(leaves[ap["index"]], path).hex() == c["root"]
            assert core.audit_path(ap["index"], leaves) == path


def test_records():
    for r in load("04-record")["records"]:
        got = core.content_root(fields_for_root(r["fields"]))
        assert got.hex() == r["content_root"], r["seq"]


def test_chain():
    for s in load("05-chain")["streams"]:
        assert core.genesis(s["stream_id"]).hex() == s["genesis"]
        prev = bytes.fromhex(s["genesis"])
        for l in s["links"]:
            prev = core.link(prev, l["seq"], bytes.fromhex(l["content_root"]), l["ts"])
            assert prev.hex() == l["link"], (s["stream_id"], l["seq"])


def test_redaction_preserves_content_root():
    d = load("06-redaction")
    after = core.content_root(fields_for_root(d["fields_after"]))
    assert after.hex() == d["content_root_after"]
    assert d["content_root_after"] == d["content_root_before"]
    for f in d["fields_after"]:
        if "leaf" in f:
            assert "salt" not in f and "s" not in f and "b" not in f


def test_segments():
    links = {}
    for s in load("05-chain")["streams"]:
        links[s["stream_id"]] = {l["seq"]: bytes.fromhex(l["link"]) for l in s["links"]}
    for c in load("07-segment")["cases"]:
        ls = [links[c["stream_id"]][q] for q in range(c["first_seq"], c["last_seq"] + 1)]
        root = core.seg_root(ls)
        assert root.hex() == c["segment_root"]
        ck = core.seg_ckpt(c["stream_id"], c["period_id"], c["first_seq"],
                           c["last_seq"], c["count"],
                           bytes.fromhex(c["link_before"]),
                           bytes.fromhex(c["link_last"]), root,
                           bytes.fromhex(c["prev_checkpoint"]))
        assert ck.hex() == c["checkpoint"]


def test_day():
    d = load("08-day")
    assert d["streams"] == sorted(d["streams"])
    ckpts = [bytes.fromhex(x) for x in d["segment_checkpoints"]]
    root = core.day_root(ckpts)
    assert root.hex() == d["day_root"]
    ck = core.day_ckpt(d["realm_id"], d["date"], len(ckpts), root,
                       bytes.fromhex(d["prev_checkpoint"]))
    assert ck.hex() == d["day_checkpoint"] == d["anchored_target"]


def test_inclusion_end_to_end():
    d = load("09-inclusion")
    rec = next(r for r in load("04-record")["records"] if r["seq"] == d["seq"])
    assert core.content_root(fields_for_root(rec["fields"])).hex() == d["content_root"]
    leaf = core.seg_leaf(bytes.fromhex(d["link"]))
    assert leaf.hex() == d["segment_leaf"]
    sp = [(s["side"], bytes.fromhex(s["h"])) for s in d["segment_path"]]
    assert core.apply_path(leaf, sp).hex() == d["segment_root"]
    dl = core.day_leaf(bytes.fromhex(d["segment_checkpoint"]))
    assert dl.hex() == d["day_leaf"]
    dp = [(s["side"], bytes.fromhex(s["h"])) for s in d["day_path"]]
    assert core.apply_path(dl, dp).hex() == d["day_root"]


@pytest.mark.parametrize("label,fn", [
    ("запись без полей", lambda: core.content_root([])),
    ("повтор имени поля", lambda: core.content_root([
        {"name": "a", "salt": b"\x00" * 16, "value": b"1"},
        {"name": "a", "salt": b"\x01" * 16, "value": b"2"}])),
    ("пустое дерево", lambda: core.mth([])),
    ("соль не 16 байт", lambda: core.field_leaf("a", b"\x00" * 8, b"v")),
    ("пустое имя поля", lambda: core.field_leaf("", b"\x00" * 16, b"v")),
    ("seq меньше 1", lambda: core.link(core.ZERO32, 0, core.ZERO32, 0)),
    ("отрицательное время", lambda: core.link(core.ZERO32, 1, core.ZERO32, -1)),
    ("отрицательный varint", lambda: core.varint(-1)),
    ("count не совпадает", lambda: core.seg_ckpt(
        "s", "2026-03-12", 1, 5, 4, core.ZERO32, core.ZERO32,
        core.ZERO32, core.ZERO32)),
    ("сторона не left/right", lambda: core.apply_path(
        core.ZERO32, [("middle", core.ZERO32)])),
])
def test_must_be_rejected(label, fn):
    with pytest.raises(core.FormatError):
        fn()
