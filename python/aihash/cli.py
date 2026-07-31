"""Командная строка aihash.

Вывод верификатора — не «OK», а фраза, которую можно вставить в письмо.
Любое несовпадение называет конкретное место, потому что «не сошлось» без
указания места бесполезно в споре.

Коды возврата проверки пакета:
  0 — сходится и запечатано: содержимое доказано
  3 — сходится, но пломба не поставлена либо не подтверждена здесь: НЕ доказано
  1 — не сходится
  2 — файл не прочитан

Код 3 объединяет два разных случая намеренно: и там, и там неизменность не
доказана. Словами их различать обязательно — «пломбы нет» вместо «пломба не
подтверждена» занижает доказательство исправного журнала.

Отдельный код для «не подтверждено» существует потому, что автоматическая
проверка смотрит на код возврата. Ноль на пакете без пломбы означал бы «всё в
порядке» там, где не доказано ничего.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from . import anchors as anchors_mod
from . import bundle, core, journal, retention, seal, sinks, store, verify

DEFAULT_ANCHORS = "rfc3161,opentimestamps,feed"


def _full(ms: Optional[int]) -> str:
    if ms is None:
        return "—"
    return time.strftime("%d.%m.%Y %H:%M UTC", time.gmtime(ms / 1000))


def _config(args) -> dict:
    cfg = {}
    if getattr(args, "tsa_url", None):
        cfg["tsa_url"] = args.tsa_url
    if getattr(args, "tsa_ca", None):
        cfg["tsa_ca"] = args.tsa_ca
    if getattr(args, "trust_store", None):
        cfg["trust_store"] = args.trust_store
    if getattr(args, "feed_path", None):
        cfg["feed_path"] = args.feed_path
    return cfg


# --- команды ----------------------------------------------------------------


def cmd_seal(args) -> int:
    layout = store.Layout(args.root)
    realm = layout.realm()
    dates = [args.date] if args.date else _open_dates(layout)
    if not dates:
        print("нечего закрывать")
        return 0
    kinds = [k.strip() for k in args.anchor.split(",") if k.strip()]
    rc = 0
    for date in dates:
        day = seal.seal_day(layout, realm["realm_id"], date,
                            allow_open=args.force)
        if day is None:
            print("%s: записей нет" % date)
            continue
        print("%s: закрыто, потоков %d, суточная отметка %s"
              % (date, len(day["streams"]), day["day_checkpoint"][:16] + "…"))
        if args.no_anchor:
            continue
        results = seal.anchor_day(layout, date, kinds, _config(args))
        for r in results:
            if r["ok"]:
                extra = " (лента не опубликована вовне)" if (
                    r["type"] == "feed" and not r.get("published")) else ""
                print("  пломба %s поставлена%s" % (r["type"], extra))
            else:
                print("  пломба %s не поставлена: %s" % (r["type"], r["error"]))
        if not any(r["ok"] for r in results):
            print("  ни одна пломба не поставлена — сутки остаются незапечатанными")
            rc = 1
        if args.archive:
            targets = _sinks_for(args, layout)
            if not targets:
                print("  архив пропущен: приёмники не заданы")
                continue
            policy = retention.load(layout) or retention.Policy()
            res = sinks.archive_date(layout, targets, date, policy.retain_until(date))
            retention.write_receipt(layout, date, res)
            print("  уложено в архив: артефактов %d, хранить до %s"
                  % (res["artifacts"], policy.retain_until(date).date().isoformat()))
    return rc


def _open_dates(layout: store.Layout) -> list:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    out = set()
    for s in layout.streams():
        for p in layout.periods(s):
            if p < today and layout.read_segment_ckpt(s, p) is None:
                out.add(p)
    return sorted(out)


def _sinks_for(args, layout) -> list:
    specs = list(getattr(args, "sink", None) or [])
    if not specs:
        policy = retention.load(layout)
        specs = policy.sinks if policy else []
    out = []
    for spec in specs:
        try:
            out.append(sinks.from_spec(spec))
        except sinks.SinkError as e:
            print("приёмник %s недоступен: %s" % (spec, e), file=sys.stderr)
    return out


def cmd_archive(args) -> int:
    layout = store.Layout(args.root)
    policy = retention.load(layout) or retention.Policy()
    targets = _sinks_for(args, layout)
    if not targets:
        print("не задан ни один приёмник: --sink local:/путь или "
              "aihash retention --set-sink ...", file=sys.stderr)
        return 2

    dates = [args.date] if args.date else [
        d for d in layout.dates()
        if args.force or not retention.read_receipt(layout, d)]
    if not dates:
        print("нечего укладывать: всё запечатанное уже в архиве")
        return 0

    rc = 0
    for date in dates:
        try:
            res = sinks.archive_date(layout, targets, date, policy.retain_until(date))
        except sinks.SinkError as e:
            print("%s: %s" % (date, e), file=sys.stderr)
            rc = 1
            continue
        if args.verify:
            chk = sinks.verify_copies(layout, targets, date)
            res["verified"] = chk
            if not chk["ok"]:
                res.setdefault("problems", []).extend(chk["missing"] + chk["differs"])
        retention.write_receipt(layout, date, res)
        names = sorted({w["sink"] for w in res["written"]})
        print("%s: уложено артефактов %d в %s, хранить до %s"
              % (date, res["artifacts"], ", ".join(names),
                 policy.retain_until(date).date().isoformat()))
        for w in res["written"]:
            if w.get("lock_mode"):
                print("  %s: блокировка %s" % (w["key"], w["lock_mode"]))
        if res.get("problems"):
            for p in res["problems"]:
                print("  не уложено: %s" % p, file=sys.stderr)
            rc = 1
        elif args.verify:
            print("  сверено копий: %d, расхождений нет" % res["verified"]["checked"])
    for t in targets:
        d = t.describe()
        print("  приёмник %s: %s" % (d["sink"], d["honest_note"]))
    return rc


def cmd_retention(args) -> int:
    layout = store.Layout(args.root)
    if args.set_years or args.set_sink:
        cur = retention.load(layout) or retention.Policy()
        policy = retention.Policy(
            args.set_years or cur.years,
            (args.set_mode or cur.mode).upper(),
            list(args.set_sink) if args.set_sink else cur.sinks)
        retention.save(layout, policy)
        print("политика записана: %d лет, режим %s, приёмники: %s"
              % (policy.years, policy.mode.lower(),
                 ", ".join(policy.sinks) or "не заданы"))
    st = retention.status(layout)
    if args.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
    else:
        print(retention.format_report(st))
    return 0 if st["ok"] else 1


def cmd_verify(args) -> int:
    path = args.path
    if os.path.isdir(path):
        return _verify_journal(path, _config(args), args.json)
    return _verify_bundle(path, _config(args), args.json)


def _verify_journal(path: str, cfg: dict, as_json: bool) -> int:
    r = verify.verify_journal(path, cfg)
    if as_json:
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
        return 0 if r.ok else 1
    if not r.ok:
        print("DOES NOT MATCH\n")
        for p in r.problems:
            print("  " + p)
        return 1
    print("Journal %s: %d record(s), %d stream(s)"
          % (r.realm["realm_id"], r.records, len(r.streams)))
    for s in r.streams:
        red = ", %d fields redacted" % s["redacted"] if s["redacted"] else ""
        print("  stream %s: %d record(s)%s" % (s["stream_id"], s["records"], red))
    sealed = [d for d in r.days if d["status"] == verify.SEALED]
    unconfirmed = [d for d in r.days if d["status"] == verify.UNVERIFIED]
    openn = [d for d in r.days if d["status"] == verify.OPEN]
    print("The chain matches end to end.")
    if sealed:
        print("Days sealed: %d (%s)"
              % (len(sealed), ", ".join(d["date"] for d in sealed)))
        for d in sealed:
            for a in d["anchors"]:
                print("  %s: %s — %s" % (d["date"], a["type"], a.get("detail", "")))
    if unconfirmed:
        _print_unconfirmed(unconfirmed)
    if openn:
        print("Days not sealed: %d (%s) — a seal is placed once a day"
              % (len(openn), ", ".join(d["date"] for d in openn)))
    return 0


# Чего не хватает для подтверждения и где это взять. Без второй половины
# сообщение бесполезно: получатель узнаёт, что проверка неполна, и не узнаёт,
# как её достроить.
_HOW_TO_CONFIRM = {
    "rfc3161": "obtain the timestamp authority root certificate from the "
               "authority itself (not from this bundle) and retry: "
               "aihash verify <journal> --tsa-ca <cacert.pem>",
    "opentimestamps": "install the client and retry: "
                      "pip install opentimestamps-client",
}


def _print_unconfirmed(days: list) -> None:
    """Пломба стоит, но подтвердить её нечем.

    Это отдельный случай, а не разновидность «не запечатано». Сказать здесь
    «пломбы нет» значит недооценить доказательство за владельца журнала —
    ошибка того же рода, что и ложное обвинение, только в другую сторону.
    """
    print("Seal present but not confirmed here: %d day(s) (%s)"
          % (len(days), ", ".join(d["date"] for d in days)))
    kinds = []
    for d in days:
        for a in d["anchors"]:
            if a["status"] != anchors_mod.UNVERIFIED or not a.get("placed"):
                continue
            print("  %s: %s — %s" % (d["date"], a["type"], a.get("detail", "")))
            if a["type"] not in kinds:
                kinds.append(a["type"])
    # Сильнее этого утверждать нельзя: что пломба относится именно к этой
    # отметке, доказано только для rfc3161 — там это видно по сырым байтам, и
    # так и написано в его строке выше. Для остальных типов проверка не
    # доведена до конца, и объявлять их относящимися к отметке — переоценивание.
    print("  This is not \"no seal\": a seal was placed for these days, "
          "verifying it was not finished.")
    for kind in kinds:
        how = _HOW_TO_CONFIRM.get(kind)
        if how:
            print("  %s: %s" % (kind, how))


RC_OK, RC_BROKEN, RC_NOT_PROVEN = 0, 1, 3


def _bundle_rc(status: str) -> int:
    if status == verify.BROKEN:
        return RC_BROKEN
    return RC_OK if status == verify.SEALED else RC_NOT_PROVEN


def _verify_bundle(path: str, cfg: dict, as_json: bool) -> int:
    r = verify.verify_bundle(path, cfg)
    if as_json:
        print(json.dumps({k: v for k, v in r.items() if k != "records"},
                         ensure_ascii=False, indent=2, default=str))
        return _bundle_rc(r["status"])

    if r["status"] == verify.BROKEN:
        print("DOES NOT MATCH\n")
        for p in r["problems"]:
            print("  " + p)
        print("\nThe previous content is not stored and cannot be recovered —")
        print("only the fingerprint is kept. Which field was changed cannot be")
        print("told from the fingerprint: it covers the record as a whole.")
        return 1

    m = r["manifest"]
    b = r.get("bounds", {})
    print("Bundle %s" % os.path.basename(path))
    print("  journal %s, stream %s, segment %s"
          % (m["realm_id"], m["stream_id"], m["period_id"]))
    print("  %d of %d records in the segment disclosed"
          % tuple(m["disclosed_of_total"]))
    print()
    for c in r["checks"]:
        print("  matches: %s" % c["label"])
    print()
    for a in r.get("anchors", []):
        mark = {"ok": "verified", "unverified": "not verified",
                "failed": "DOES NOT MATCH"}[a["status"]]
        print("  seal %s: %s — %s" % (a["type"], mark, a.get("detail", "")))
    print()
    if r["status"] == verify.SEALED:
        print("Verdict: the content matches its fingerprint, the fingerprint is")
        print("in the daily tree, and the daily checkpoint is sealed.")
    elif r["status"] == verify.UNVERIFIED:
        print("Verdict: the content matches its fingerprint and is in the daily tree.")
        print("A seal was placed for these days but is not confirmed here — see")
        print("its line above. Integrity is not proven until verifying the seal")
        print("is finished; this is not the same as having no seal.")
    else:
        print("Verdict: the content matches its fingerprint and is in the daily tree,")
        print("but no seal was placed for these days. Integrity is not proven —")
        print("only internal consistency is.")
    lo = _full(b.get("lower_ms")) if b.get("lower_ms") else None
    if lo:
        print("The record existed no earlier than %s (%s)" % (lo, b["lower_source"]))
    if b.get("upper"):
        print("and no later than %s (%s)." % (b["upper"], b["upper_source"]))
    return _bundle_rc(r["status"])


def cmd_explain(args) -> int:
    seqs = [int(x) for x in args.seq.split(",")]
    out = args.out or ("%s-%s.seal" % (args.stream, "-".join(map(str, seqs))))
    bundle.build(args.root, args.stream, seqs, out, _config(args))
    if getattr(args, "tsa_ca", None):
        print("в пакет вложен сертификат службы штампов — получателю не нужна сеть")
    import zipfile
    with zipfile.ZipFile(out) as z:
        if "verify.html" not in z.namelist():
            print("страница-верификатор в пакет не вошла — соберите её: "
                  "python3 verifier/build.py", file=sys.stderr)
    print("собран %s" % out)
    print("проверка у получателя:  aihash verify %s" % os.path.basename(out))
    return 0


def cmd_redact(args) -> int:
    layout = store.Layout(args.root)
    period = _period_of(layout, args.stream, args.seq)
    j = journal.Journal(args.root, _realm_of(args.root), beacon_source=None)
    try:
        seq = j.stream(args.stream).redact(
            args.seq, [f.strip() for f in args.fields.split(",")], args.reason)
        print("вычеркнуто из записи %d; событие записано как %d" % (args.seq, seq))
        print("отпечаток записи не изменился, цепь продолжает сходиться")
    finally:
        j.close()
    return _warn_about_archived_copies(layout, period)


def _period_of(layout: store.Layout, stream_id: str, seq: int):
    for p in layout.periods(stream_id):
        recs = layout.read_segment(stream_id, p)
        if recs and recs[0]["seq"] <= seq <= recs[-1]["seq"]:
            return p
    return None


def _warn_about_archived_copies(layout: store.Layout, period) -> int:
    """Вычёркивание правит журнал, но не копию в архиве.

    Молчать об этом нельзя: клиент, применивший обе возможности как написано в
    документации, окажется не в состоянии исполнить требование об удалении по
    уже уложенным суткам — и узнает об этом от проверяющего органа.
    """
    if period is None:
        return 0
    targets = retention.archived_sinks(layout, period)
    if not targets:
        return 0
    print()
    print("ВНИМАНИЕ: сутки %s уже уложены в архив, и там осталась прежняя копия."
          % period, file=sys.stderr)
    rc = 0
    for t in targets:
        if t.get("lock_mode"):
            print("  приёмник %s: режим %s — прежнюю версию удалить нельзя до "
                  "истечения срока хранения. Требование об удалении по этим "
                  "суткам средствами aihash не исполняется."
                  % (t["sink"], t["lock_mode"]), file=sys.stderr)
            rc = 1
        else:
            print("  приёмник %s: переуложите архив, чтобы вычёркивание дошло "
                  "и туда:" % t["sink"], file=sys.stderr)
            print("    aihash archive --root %s --date %s --force"
                  % (layout.root, period), file=sys.stderr)
    return rc


def cmd_ls(args) -> int:
    layout = store.Layout(args.root)
    realm = layout.realm()
    print("журнал %s, формат %s" % (realm["realm_id"], realm["format"]))
    for s in layout.streams():
        print("  поток %s" % s)
        for p in layout.periods(s):
            recs = layout.read_segment(s, p)
            ck = layout.read_segment_ckpt(s, p)
            anchors = [os.path.basename(a) for a in layout.anchors_for(p)]
            day = layout.read_day(p)
            feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
            if day and os.path.exists(feed):
                res = anchors_mod.verify_file(
                    feed, bytes.fromhex(day["day_checkpoint"]))
                if res["status"] == anchors_mod.OK:
                    anchors.append("feed.jsonl")
            state = "запечатан" if (ck and anchors) else (
                "закрыт, без пломбы" if ck else "открыт")
            print("    %s: записей %d, %s%s"
                  % (p, len(recs), state,
                     (" [" + ", ".join(anchors) + "]") if anchors else ""))
    return 0


def _realm_of(root: str) -> str:
    return store.Layout(root).realm()["realm_id"]


# --- разбор аргументов ------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aihash", description="Доказуемый журнал работы ИИ-системы")
    sub = p.add_subparsers(dest="cmd", required=True)

    def anchors_args(sp):
        sp.add_argument("--tsa-url", help="служба штампов времени RFC 3161")
        sp.add_argument("--tsa-ca",
                        help="корневой сертификат службы штампов — "
                             "переопределение вшитого набора корней, "
                             "для служб, которых в нём нет")
        sp.add_argument("--trust-store",
                        help="свой набор корней вместо вшитого")
        sp.add_argument("--feed-path", help="путь к публикуемой ленте отпечатков")

    s = sub.add_parser("seal", help="закрыть сутки и поставить пломбы")
    s.add_argument("--root", required=True)
    s.add_argument("--date", help="ГГГГ-ММ-ДД; по умолчанию все незакрытые")
    s.add_argument("--anchor", default=DEFAULT_ANCHORS)
    s.add_argument("--no-anchor", action="store_true")
    s.add_argument("--archive", action="store_true",
                   help="сразу уложить запечатанные сутки в приёмники")
    s.add_argument("--sink", action="append",
                   help="local:/путь или s3://корзина/префикс; можно несколько")
    s.add_argument("--force", action="store_true",
                   help="закрыть текущие сутки; после этого поток начнёт новый "
                        "отрезок только на следующие сутки")
    anchors_args(s)
    s.set_defaults(func=cmd_seal)

    v = sub.add_parser("verify", help="проверить журнал или пакет .seal")
    v.add_argument("path")
    v.add_argument("--json", action="store_true")
    anchors_args(v)
    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("explain", help="собрать пакет доказательства")
    e.add_argument("--root", required=True)
    e.add_argument("--stream", required=True)
    e.add_argument("--seq", required=True, help="номер или список через запятую")
    e.add_argument("--out")
    anchors_args(e)
    e.set_defaults(func=cmd_explain)

    rd = sub.add_parser("redact", help="вычеркнуть значения полей")
    rd.add_argument("--root", required=True)
    rd.add_argument("--stream", required=True)
    rd.add_argument("--seq", type=int, required=True)
    rd.add_argument("--fields", required=True)
    rd.add_argument("--reason", required=True)
    rd.set_defaults(func=cmd_redact)

    a = sub.add_parser("archive", help="уложить запечатанные сутки в приёмники")
    a.add_argument("--root", required=True)
    a.add_argument("--date", help="ГГГГ-ММ-ДД; по умолчанию всё неуложенное")
    a.add_argument("--sink", action="append",
                   help="local:/путь или s3://корзина/префикс; можно несколько")
    a.add_argument("--verify", action="store_true",
                   help="прочитать архив обратно и сверить байты")
    a.add_argument("--force", action="store_true",
                   help="переуложить уже уложенные сутки (после вычёркивания)")
    a.set_defaults(func=cmd_archive)

    rt = sub.add_parser("retention", help="сохранность: политика и пробелы")
    rt.add_argument("--root", required=True)
    rt.add_argument("--set-years", type=int, help="сколько лет хранить")
    rt.add_argument("--set-mode", help="COMPLIANCE или GOVERNANCE")
    rt.add_argument("--set-sink", action="append", help="приёмник по умолчанию")
    rt.add_argument("--json", action="store_true")
    rt.set_defaults(func=cmd_retention)

    ls = sub.add_parser("ls", help="что лежит в журнале")
    ls.add_argument("--root", required=True)
    ls.set_defaults(func=cmd_ls)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except core.FormatError as e:
        print("ошибка формата: %s" % e, file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print("файл не найден: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
