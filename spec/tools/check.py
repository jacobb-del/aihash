"""Проверка тестовых векторов aihash v1.

Запуск:  python3 spec/tools/check.py

Читает файлы векторов и пересчитывает каждое значение заново из объявленных
входных данных. Сторонняя реализация должна воспроизвести эту же процедуру и
получить те же результаты — это и есть конформанс.

Код возврата: 0 — всё сошлось, 1 — расхождение.
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ref  # noqa: E402

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors")

passed = 0
failed = []


def eq(label, got, want):
    global passed
    got = got.hex() if isinstance(got, bytes) else got
    if got == want:
        passed += 1
    else:
        failed.append("%s\n    ожидалось %s\n    получено  %s" % (label, want, got))


def load(name):
    with open(os.path.join(V, name + ".json"), encoding="utf-8") as f:
        return json.load(f)


def raw_value(f):
    if "s" in f and "b" in f:
        raise ValueError("поле не может иметь одновременно s и b")
    if "s" in f:
        return f["s"].encode("utf-8")
    return base64.b64decode(f["b"])


def fields_for_root(fields):
    out = []
    for f in fields:
        if "leaf" in f:
            out.append(dict(name=f["name"], leaf=bytes.fromhex(f["leaf"])))
        else:
            out.append(dict(name=f["name"], salt=bytes.fromhex(f["salt"]),
                            value=raw_value(f)))
    return out


def check_varint():
    for c in load("01-varint")["cases"]:
        eq("varint(%d)" % c["value"], ref.varint(c["value"]), c["hex"])


def check_field_leaf():
    for c in load("02-field-leaf")["cases"]:
        eq("лист поля %s" % c["name"],
           ref.field_leaf(c["name"], bytes.fromhex(c["salt"]), raw_value(c)), c["leaf"])


def check_merkle():
    for c in load("03-merkle")["cases"]:
        leaves = [bytes.fromhex(x) for x in c["leaves"]]
        eq("корень дерева n=%d" % c["n"], ref.mth(leaves), c["root"])
        for ap in c["audit_paths"]:
            path = [(s["side"], bytes.fromhex(s["h"])) for s in ap["path"]]
            eq("путь n=%d i=%d" % (c["n"], ap["index"]),
               ref.apply_path(leaves[ap["index"]], path), c["root"])


def check_records():
    for r in load("04-record")["records"]:
        eq("отпечаток содержимого seq=%d" % r["seq"],
           ref.content_root(fields_for_root(r["fields"])), r["content_root"])


def check_chain():
    recs = {r["seq"]: r for r in load("04-record")["records"]}
    for s in load("05-chain")["streams"]:
        eq("нулевое звено %s" % s["stream_id"], ref.genesis(s["stream_id"]), s["genesis"])
        prev = bytes.fromhex(s["genesis"])
        for l in s["links"]:
            if s["stream_id"] == "voice-eu-3":
                eq("звено сверено с записью seq=%d" % l["seq"],
                   recs[l["seq"]]["content_root"], l["content_root"])
            prev = ref.link(prev, l["seq"], bytes.fromhex(l["content_root"]), l["ts"])
            eq("звено %s seq=%d" % (s["stream_id"], l["seq"]), prev, l["link"])


def check_redaction():
    d = load("06-redaction")
    root = ref.content_root(fields_for_root(d["fields_after"]))
    eq("отпечаток после вычёркивания", root, d["content_root_after"])
    eq("отпечаток не изменился вычёркиванием",
       d["content_root_after"], d["content_root_before"])
    for f in d["fields_after"]:
        if "leaf" in f and ("salt" in f or "s" in f or "b" in f):
            failed.append("вычеркнутое поле %s сохранило соль или значение" % f["name"])


def check_segments():
    links = {}
    for s in load("05-chain")["streams"]:
        links[s["stream_id"]] = {l["seq"]: bytes.fromhex(l["link"]) for l in s["links"]}
    for c in load("07-segment")["cases"]:
        ls = [links[c["stream_id"]][q] for q in range(c["first_seq"], c["last_seq"] + 1)]
        root = ref.seg_root(ls)
        eq("корень отрезка %s %s" % (c["stream_id"], c["period_id"]), root, c["segment_root"])
        eq("отметка отрезка %s %s" % (c["stream_id"], c["period_id"]),
           ref.seg_ckpt(c["stream_id"], c["period_id"], c["first_seq"], c["last_seq"],
                        c["count"], bytes.fromhex(c["link_before"]),
                        bytes.fromhex(c["link_last"]), root,
                        bytes.fromhex(c["prev_checkpoint"])), c["checkpoint"])


def check_day():
    d = load("08-day")
    segs = {(c["stream_id"], c["period_id"]): c["checkpoint"]
            for c in load("07-segment")["cases"]}
    for s, ck in zip(d["streams"], d["segment_checkpoints"]):
        eq("отметка отрезка %s взята из 07" % s, segs[(s, d["date"])], ck)
    eq("потоки отсортированы по stream_id", d["streams"], sorted(d["streams"]))
    ckpts = [bytes.fromhex(x) for x in d["segment_checkpoints"]]
    root = ref.day_root(ckpts)
    eq("суточный корень", root, d["day_root"])
    eq("суточная отметка",
       ref.day_ckpt(d["realm_id"], d["date"], len(ckpts), root,
                    bytes.fromhex(d["prev_checkpoint"])), d["day_checkpoint"])
    eq("под пломбу уходит суточная отметка", d["anchored_target"], d["day_checkpoint"])


def check_inclusion():
    d = load("09-inclusion")
    rec = next(r for r in load("04-record")["records"] if r["seq"] == d["seq"])
    eq("сквозной путь: отпечаток содержимого",
       ref.content_root(fields_for_root(rec["fields"])), d["content_root"])
    leaf = ref.seg_leaf(bytes.fromhex(d["link"]))
    eq("сквозной путь: лист отрезка", leaf, d["segment_leaf"])
    sp = [(s["side"], bytes.fromhex(s["h"])) for s in d["segment_path"]]
    eq("сквозной путь: корень отрезка", ref.apply_path(leaf, sp), d["segment_root"])
    dl = ref.day_leaf(bytes.fromhex(d["segment_checkpoint"]))
    eq("сквозной путь: лист суток", dl, d["day_leaf"])
    dp = [(s["side"], bytes.fromhex(s["h"])) for s in d["day_path"]]
    eq("сквозной путь: суточный корень", ref.apply_path(dl, dp), d["day_root"])


def check_negative():
    """Свойства, которые обязаны отвергаться. Реализация, которая их принимает,
    не соответствует спецификации, даже если все положительные векторы сошлись."""
    cases = [
        ("запись без полей", lambda: ref.content_root([])),
        ("повтор имени поля", lambda: ref.content_root([
            dict(name="a", salt=b"\x00" * 16, value=b"1"),
            dict(name="a", salt=b"\x01" * 16, value=b"2")])),
        ("пустое дерево", lambda: ref.mth([])),
        ("соль не 16 байт", lambda: ref.field_leaf("a", b"\x00" * 8, b"v")),
        ("пустое имя поля", lambda: ref.field_leaf("", b"\x00" * 16, b"v")),
        ("seq меньше 1", lambda: ref.link(ref.ZERO32, 0, ref.ZERO32, 0)),
        ("отрицательный varint", lambda: ref.varint(-1)),
        ("count не совпадает с диапазоном", lambda: ref.seg_ckpt(
            "s", "2026-03-12", 1, 5, 4, ref.ZERO32, ref.ZERO32, ref.ZERO32, ref.ZERO32)),
    ]
    global passed
    for label, fn in cases:
        try:
            fn()
        except ValueError:
            passed += 1
        else:
            failed.append("должно было быть отвергнуто: %s" % label)


def main():
    for fn in [check_varint, check_field_leaf, check_merkle, check_records,
               check_chain, check_redaction, check_segments, check_day,
               check_inclusion, check_negative]:
        fn()
    print("сошлось проверок: %d" % passed)
    if failed:
        print("расхождений: %d\n" % len(failed))
        for f in failed:
            print("  " + f)
        return 1
    print("расхождений нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
