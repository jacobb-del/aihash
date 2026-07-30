"""Сборка пакета доказательства .seal.

Пакет самодостаточен: проверка не требует сети, наших серверов, установки
чего-либо и учётной записи. Раскрывается только то, что положили в пакет —
остальные записи журнала в нём отсутствуют и по нему невосстановимы.

Отдавать оппоненту весь журнал юридически неприемлемо, поэтому короткое
доказательство на одну запись — требование, а не оптимизация.
"""

from __future__ import annotations

import json
import logging
import os
import time
import zipfile
from typing import List, Optional, Sequence

from . import core, report, store
from .seal import segment_links

log = logging.getLogger("aihash")

VERIFY_TXT = """Как проверить этот файл

Это пакет доказательства формата aihash/1. Он подтверждает, что перечисленные
в нём записи существовали в указанный промежуток времени и с тех пор не
менялись.

Проверка выполняется у вас, без обращения к тому, кто выдал этот файл, и без
доступа в интернет:

    aihash-verify {name}

либо, если ставить ничего не хотите, откройте verify.html из этого архива
двойным щелчком и перетащите в неё этот же файл;
либо возьмите бинарь aihash-verify — он ни от чего не зависит:

    aihash-verify {name}

ВАЖНО. Verify.html лежит здесь для удобства, но приложила его сторона, которая
этот файл выдала. Если спор острый, возьмите verify.html из открытого проекта
и сверьте его отпечаток — файл один, зависимостей у него нет, и прочитать его
целиком может любой специалист. Верификатор, полученный от оппонента, — не
независимая проверка.

Внутри пакета:

  report.html     выписка обычным языком, одна страница
  records.jsonl   раскрытые записи вместе с солями
  proofs.json     пути в дереве отпечатков
  segment.json    отметка отрезка
  day.json        суточная отметка — то, на что поставлена пломба
  anchors/        сами пломбы
  verify.html     верификатор — один файл, открывается двойным щелчком
  certs/          сертификат службы штампов, если он был приложен
  manifest.json   что именно раскрыто

Пакет намеренно собран без сжатия: чтобы верификатору не требовался
распаковщик и он оставался читаемым целиком.

Чего пакет НЕ доказывает: что записи правдивы, что журнал полон, и кто именно
их написал. Он доказывает, что содержимое не менялось после постановки пломбы
и что оно существовало в указанном промежутке.
"""


def build(root: str, stream_id: str, seqs: Sequence[int], out_path: str,
          config: Optional[dict] = None) -> str:
    config = config or {}
    layout = store.Layout(root)
    realm = layout.realm()
    seqs = sorted(set(seqs))

    period = _period_of_seq(layout, stream_id, seqs[0])
    for s in seqs:
        if _period_of_seq(layout, stream_id, s) != period:
            raise core.FormatError(
                "записи %s лежат в разных отрезках — соберите отдельные пакеты"
                % seqs)

    seg = layout.read_segment_ckpt(stream_id, period)
    if seg is None:
        raise core.FormatError(
            "отрезок %s ещё не закрыт — сначала aihash seal --date %s"
            % (period, period))
    day = layout.read_day(period)
    if day is None:
        raise core.FormatError("сутки %s не закрыты" % period)

    recs = layout.read_segment(stream_id, period)
    by_seq = {r["seq"]: r for r in recs}
    missing = [s for s in seqs if s not in by_seq]
    if missing:
        raise core.FormatError("нет записей: %s" % missing)

    links = _segment_links(layout, stream_id, period, recs, seg)
    seg_leaves = [core.seg_leaf(links[r["seq"]]) for r in recs]
    index_of = {r["seq"]: i for i, r in enumerate(recs)}

    proofs = {"records": {}, "day_path": []}
    for s in seqs:
        prev_link = links[s - 1] if s - 1 in links else \
            bytes.fromhex(seg["link_before"])
        path = core.audit_path(index_of[s], seg_leaves)
        proofs["records"][str(s)] = {
            "prev_link": prev_link.hex(), "link": links[s].hex(),
            "leaf_index": index_of[s],
            "segment_path": [{"side": sd, "h": h.hex()} for sd, h in path]}

    ckpts = [bytes.fromhex(c) for c in day["segment_checkpoints"]]
    dpath = core.audit_path(day["streams"].index(stream_id),
                            [core.day_leaf(c) for c in ckpts])
    proofs["day_path"] = [{"side": sd, "h": h.hex()} for sd, h in dpath]

    manifest = {"format": core.FORMAT_VERSION, "hash": core.HASH_NAME,
                "realm_id": realm["realm_id"], "stream_id": stream_id,
                "period_id": period, "seqs": seqs,
                "created": int(time.time() * 1000),
                "beacon": _beacon_of(recs),
                "disclosed_of_total": [len(seqs), seg["count"]]}

    anchor_paths = [p for p in layout.anchors_for(period)]
    feed = config.get("feed_path") or os.path.join(layout.anchors_dir(), "feed.jsonl")
    if os.path.exists(feed):
        anchor_paths.append(feed)

    html = report.render(manifest, [by_seq[s] for s in seqs], seg, day, anchor_paths)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        z.writestr("records.jsonl", "\n".join(
            json.dumps(by_seq[s], ensure_ascii=False, separators=(",", ":"))
            for s in seqs) + "\n")
        z.writestr("proofs.json", json.dumps(proofs, ensure_ascii=False, indent=2))
        z.writestr("segment.json", json.dumps(seg, ensure_ascii=False, indent=2))
        z.writestr("day.json", json.dumps(day, ensure_ascii=False, indent=2))
        for p in anchor_paths:
            with open(p, "rb") as f:
                z.writestr("anchors/" + os.path.basename(p), f.read())
        # Сертификат службы штампов кладётся ВНЕ anchors/, чтобы верификаторы
        # не приняли его за пломбу неизвестного типа. Без него подпись штампа
        # офлайн не проверить, а проверка обязана работать без сети.
        ca = config.get("tsa_ca")
        if ca and os.path.exists(ca):
            with open(ca, "rb") as f:
                z.writestr("certs/rfc3161-ca.pem", f.read())
        z.writestr("report.html", html)
        page = _verifier_page()
        if page:
            z.writestr("verify.html", page)
        else:
            # Страница собирается verifier/build.py. Её отсутствие означает,
            # что получателю придётся искать верификатор самому — молчать об
            # этом нельзя.
            log.warning(
                "aihash: страница-верификатор не найдена (%s) — пакет собран "
                "без неё. Соберите: python3 verifier/build.py",
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "assets", "verify.html"))
        z.writestr("VERIFY.txt", VERIFY_TXT.format(name=os.path.basename(out_path)))
    return out_path


def _verifier_page() -> Optional[str]:
    """Страница-верификатор кладётся внутрь пакета: получателю не нужно ничего
    скачивать и устанавливать, чтобы проверить файл."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "assets", "verify.html")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()


def _period_of_seq(layout: store.Layout, stream_id: str, seq: int) -> str:
    for p in layout.periods(stream_id):
        recs = layout.read_segment(stream_id, p)
        if recs and recs[0]["seq"] <= seq <= recs[-1]["seq"]:
            return p
    raise core.FormatError("запись seq=%d не найдена в потоке %s" % (seq, stream_id))


def _segment_links(layout: store.Layout, stream_id: str, period: str,
                   recs: List[dict], seg: dict) -> dict:
    """Пересчитывает звенья отрезка, а не берёт записанные на веру.

    Начало — link_before из уже запечатанной отметки отрезка. Пересчёт от
    начала времён давал бы то же самое, но требовал чтения всего журнала на
    каждую сборку пакета. Сходимость проверяется тем, что пересчитанный корень
    отрезка совпадает с запечатанным.
    """
    start = bytes.fromhex(seg["link_before"])
    links = {r["seq"]: l
             for r, l in zip(recs, segment_links(layout, stream_id, period,
                                                 recs, start))}
    root = core.seg_root([links[r["seq"]] for r in recs])
    if root.hex() != seg["segment_root"]:
        raise core.FormatError(
            "поток %s, отрезок %s: пересчитанный корень не совпадает с "
            "запечатанным — пакет не собран" % (stream_id, period))
    return links


def _beacon_of(recs: List[dict]) -> Optional[dict]:
    for rec in recs:
        names = {f["name"]: f for f in rec["fields"]}
        if "_beacon.round" in names and "s" in names["_beacon.round"]:
            return {"source": names["_beacon.source"].get("s"),
                    "round": names["_beacon.round"]["s"],
                    "seq": rec["seq"]}
    return None
