"""Сборка тестовых векторов формата aihash v1.

Запуск:  python3 spec/tools/genvectors.py

Векторы вычисляются эталонной реализацией (ref.py), а не пишутся руками.
Сценарий намеренно повторяет пример из выписки: звонок про возврат 12 марта,
позднее вычёркивание персональных данных по запросу на удаление.
"""

import base64
import datetime as dt
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ref  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors")
REALM = "romashka-prod"
S_VOICE = "voice-eu-3"
S_BILL = "billing-1"


def hx(b):
    return b.hex()


def ms(y, mo, d, h, mi, s):
    return int(dt.datetime(y, mo, d, h, mi, s, tzinfo=dt.timezone.utc).timestamp() * 1000)


def write(name, payload):
    path = os.path.join(OUT, name + ".json")
    payload = dict(vector=name, format=ref.FORMAT_VERSION, **payload)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return os.path.basename(path)


def enc_value(v):
    """Значение поля в векторе: строка (s) или произвольные байты (b)."""
    if isinstance(v, str):
        return {"s": v}, v.encode("utf-8")
    return {"b": base64.b64encode(v).decode("ascii")}, v


def build_record(stream_id, seq, ts, fields):
    """fields — список (имя, значение). Возвращает представление для вектора."""
    enc, calc = [], []
    for name, val in fields:
        salt = ref.test_salt(stream_id, seq, name)
        shown, raw = enc_value(val)
        enc.append(dict(name=name, salt=hx(salt), **shown))
        calc.append(dict(name=name, salt=salt, value=raw))
    croot = ref.content_root(calc)
    return dict(seq=seq, ts=ts, fields=enc), croot, calc


# --- сценарий ---------------------------------------------------------------

BEACON_VALUE = hashlib.sha256(b"drand/quicknet/round/4821293").digest()

VOICE_MAR = [
    (1, ms(2026, 3, 12, 14, 30, 0), [
        ("_beacon.source", "drand:quicknet"),
        ("_beacon.round", "4821293"),
        ("_beacon.value", BEACON_VALUE),
    ]),
    (2, ms(2026, 3, 12, 14, 31, 2), [
        ("actor", "customer"),
        ("customer.name", "Пётр Ильич Сергеев"),
        ("customer.phone", "+7 916 555-01-72"),
        ("input.text", "Когда придёт возврат за отменённый заказ?"),
    ]),
    (3, ms(2026, 3, 12, 14, 32, 8), [
        ("actor", "assistant"),
        ("tool.name", "orders.get"),
        ("tool.result", "{\"order\":\"A-40912\",\"status\":\"cancelled\"}"),
    ]),
    (4, ms(2026, 3, 12, 14, 32, 41), [
        ("actor", "assistant"),
        ("output.text", "возврат придёт в течение 5 дней"),
        ("config.prompt_version", "v14"),
        ("config.model", "gpt-4o-2026-02-11"),
        ("config.human_review", ""),
    ]),
    (5, ms(2026, 3, 12, 14, 33, 19), [
        ("actor", "system"),
        ("billing.op", "RF-88214"),
    ]),
]

VOICE_JUN = [
    (6, ms(2026, 6, 4, 9, 12, 0), [
        ("_redaction.target_seq", "2"),
        ("_redaction.fields", "customer.name,customer.phone"),
        ("_redaction.reason", "запрос на удаление персональных данных"),
    ]),
]

BILL_MAR = [
    (1, ms(2026, 3, 12, 14, 33, 20), [
        ("actor", "system"),
        ("billing.op", "RF-88214"),
        ("billing.amount_minor", "412000"),
    ]),
    (2, ms(2026, 3, 12, 14, 33, 21), [
        ("actor", "system"),
        ("billing.state", "queued"),
    ]),
]


def chain(stream_id, batches):
    """Считает цепь по всем отрезкам потока подряд."""
    prev = ref.genesis(stream_id)
    out = []
    for records in batches:
        seg = []
        for seq, ts, fields in records:
            rec, croot, calc = build_record(stream_id, seq, ts, fields)
            link_before = prev
            prev = ref.link(prev, seq, croot, ts)
            rec["content_root"] = hx(croot)
            rec["link"] = hx(prev)
            seg.append(dict(record=rec, croot=croot, link=prev,
                            link_before=link_before, calc=calc))
        out.append(seg)
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    files = []

    # 01 — varint
    cases = []
    for n in [0, 1, 127, 128, 129, 255, 300, 16383, 16384, 2 ** 32,
              1773325862000, 1785000000123]:
        cases.append(dict(value=n, hex=hx(ref.varint(n))))
    files.append(write("01-varint", dict(
        description="LEB128 без знака. Первая точка расхождения при переносе на другой язык.",
        cases=cases)))

    # 02 — лист поля
    leaf_cases = []
    for name, val in [
        ("actor", "assistant"),
        ("output.text", "возврат придёт в течение 5 дней"),
        ("config.human_review", ""),
        ("_beacon.value", BEACON_VALUE),
        ("поле.с.юникодом", "значение\nс переводом строки"),
        ("x", b"\x00\x01\x02\xff"),
    ]:
        salt = ref.test_salt("vectors", 0, name)
        shown, raw = enc_value(val)
        leaf_cases.append(dict(name=name, salt=hx(salt), **shown,
                               leaf=hx(ref.field_leaf(name, salt, raw))))
    files.append(write("02-field-leaf", dict(
        description="Лист дерева полей. Проверяет UTF-8, пустое значение, произвольные байты.",
        salt_rule="sha256('aihash/v1/test-salt/{stream}/{seq}/{name}')[:16]",
        cases=leaf_cases)))

    # 03 — дерево и путь принадлежности
    base = [hashlib.sha256(("leaf-%d" % i).encode()).digest() for i in range(8)]
    tree_cases = []
    for n in range(1, 9):
        leaves = base[:n]
        paths = []
        for i in range(n):
            p = ref.audit_path(i, leaves)
            assert ref.apply_path(leaves[i], p) == ref.mth(leaves)
            paths.append(dict(index=i, path=[dict(side=s, h=hx(x)) for s, x in p]))
        tree_cases.append(dict(n=n, leaves=[hx(x) for x in leaves],
                               root=hx(ref.mth(leaves)), audit_paths=paths))
    files.append(write("03-merkle", dict(
        description="RFC 6962. Нечётные n (3,5,6,7) проверяют поднятие последнего узла без дублирования.",
        cases=tree_cases)))

    # цепи
    voice = chain(S_VOICE, [VOICE_MAR, VOICE_JUN])
    bill = chain(S_BILL, [BILL_MAR])

    # 04 — записи
    files.append(write("04-record", dict(
        description="Полные записи сценария и их содержательные отпечатки.",
        stream_id=S_VOICE,
        records=[e["record"] for e in voice[0]] + [e["record"] for e in voice[1]])))

    # 05 — цепь
    files.append(write("05-chain", dict(
        description="Нулевое звено и цепь. Звено связывает предыдущее звено, seq, отпечаток содержимого и заявленное время.",
        streams=[
            dict(stream_id=S_VOICE, genesis=hx(ref.genesis(S_VOICE)),
                 links=[dict(seq=e["record"]["seq"], ts=e["record"]["ts"],
                             content_root=e["record"]["content_root"],
                             link=hx(e["link"])) for seg in voice for e in seg]),
            dict(stream_id=S_BILL, genesis=hx(ref.genesis(S_BILL)),
                 links=[dict(seq=e["record"]["seq"], ts=e["record"]["ts"],
                             content_root=e["record"]["content_root"],
                             link=hx(e["link"])) for seg in bill for e in seg]),
        ])))

    # 06 — вычёркивание
    src = voice[0][1]
    redacted_fields, kept = [], []
    for f in src["calc"]:
        if f["name"] in ("customer.name", "customer.phone"):
            leaf = ref.field_leaf(f["name"], f["salt"], f["value"])
            redacted_fields.append(dict(name=f["name"], leaf=hx(leaf),
                                        redacted=dict(at=ms(2026, 6, 4, 9, 12, 0), seq=6)))
            kept.append(dict(name=f["name"], leaf=leaf))
        else:
            shown, _ = enc_value(f["value"].decode("utf-8"))
            redacted_fields.append(dict(name=f["name"], salt=hx(f["salt"]), **shown))
            kept.append(f)
    after = ref.content_root(kept)
    assert after == src["croot"], "вычёркивание изменило отпечаток записи"
    files.append(write("06-redaction", dict(
        description="Ключевое свойство: удаление значения и соли не меняет отпечаток записи и не рвёт цепь.",
        stream_id=S_VOICE, seq=2,
        content_root_before=hx(src["croot"]),
        content_root_after=hx(after),
        fields_after=redacted_fields,
        redaction_record_seq=6)))

    # 07 — отрезки
    segs, seg_out = {}, []
    prev_by_stream = {}
    for stream_id, batches, periods in [
        (S_VOICE, voice, ["2026-03-12", "2026-06-04"]),
        (S_BILL, bill, ["2026-03-12"]),
    ]:
        for seg, period in zip(batches, periods):
            links = [e["link"] for e in seg]
            root = ref.seg_root(links)
            prev = prev_by_stream.get(stream_id, ref.ZERO32)
            ck = ref.seg_ckpt(stream_id, period, seg[0]["record"]["seq"],
                              seg[-1]["record"]["seq"], len(seg),
                              seg[0]["link_before"], links[-1], root, prev)
            prev_by_stream[stream_id] = ck
            segs[(stream_id, period)] = dict(links=links, root=root, ckpt=ck)
            seg_out.append(dict(stream_id=stream_id, period_id=period,
                                first_seq=seg[0]["record"]["seq"],
                                last_seq=seg[-1]["record"]["seq"], count=len(seg),
                                link_before=hx(seg[0]["link_before"]),
                                link_last=hx(links[-1]), segment_root=hx(root),
                                prev_checkpoint=hx(prev), checkpoint=hx(ck)))
    files.append(write("07-segment", dict(
        description="Отметка отрезка. Отметки одного потока связаны между собой — иначе можно переписать целые сутки.",
        cases=seg_out)))

    # 08 — сутки
    date = "2026-03-12"
    day_streams = sorted([S_VOICE, S_BILL])
    ckpts = [segs[(s, date)]["ckpt"] for s in day_streams]
    droot = ref.day_root(ckpts)
    dckpt = ref.day_ckpt(REALM, date, len(ckpts), droot, ref.ZERO32)
    files.append(write("08-day", dict(
        description="Суточная отметка накрывает все потоки установки. Именно она уходит под пломбу.",
        realm_id=REALM, date=date,
        streams=day_streams,
        segment_checkpoints=[hx(c) for c in ckpts],
        day_root=hx(droot), prev_checkpoint=hx(ref.ZERO32),
        day_checkpoint=hx(dckpt),
        anchored_target=hx(dckpt))))

    # 09 — сквозной путь одной записи
    target = voice[0][3]
    seg = segs[(S_VOICE, date)]
    idx = 3
    sp = ref.audit_path(idx, [ref.seg_leaf(l) for l in seg["links"]])
    dp = ref.audit_path(day_streams.index(S_VOICE), [ref.day_leaf(c) for c in ckpts])
    assert ref.apply_path(ref.seg_leaf(target["link"]), sp) == seg["root"]
    assert ref.apply_path(ref.day_leaf(seg["ckpt"]), dp) == droot
    files.append(write("09-inclusion", dict(
        description="От поля записи до отпечатка под пломбой. Это содержимое пакета .seal для одной записи.",
        stream_id=S_VOICE, seq=4, period_id=date,
        content_root=hx(target["croot"]), link=hx(target["link"]),
        segment_leaf=hx(ref.seg_leaf(target["link"])), leaf_index=idx,
        segment_path=[dict(side=s, h=hx(x)) for s, x in sp],
        segment_root=hx(seg["root"]), segment_checkpoint=hx(seg["ckpt"]),
        day_leaf=hx(ref.day_leaf(seg["ckpt"])), day_leaf_index=day_streams.index(S_VOICE),
        day_path=[dict(side=s, h=hx(x)) for s, x in dp],
        day_root=hx(droot), day_checkpoint=hx(dckpt))))

    with open(os.path.join(OUT, "index.json"), "w", encoding="utf-8") as f:
        json.dump(dict(format=ref.FORMAT_VERSION, hash="sha256", files=sorted(files)),
                  f, ensure_ascii=False, indent=2)
        f.write("\n")

    print("записано векторов: %d" % len(files))
    for name in sorted(files):
        print("  " + name)


if __name__ == "__main__":
    main()
