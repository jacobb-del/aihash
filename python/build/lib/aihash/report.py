"""Выписка на одну страницу.

Правила из плана, раздел 11а:
  - время показывается интервалом, а не точкой;
  - записанное отделено от выведенного;
  - вычёркивание — строка в хронологии, а не пробел;
  - документ двухслойный: страница для человека, приложение для эксперта;
  - печать важнее экрана: одна A4, состояние обозначено словом, а не цветом.

Выписку составляет тот, кто её предъявляет, поэтому она НЕ утверждает, что
проверка пройдена. Она говорит, что и как проверить. Зелёную галочку ставит
читатель у себя, командой из блока проверки.
"""

from __future__ import annotations

import html
import os
import time
from typing import List, Optional

from . import beacon as beacon_mod

CSS = """
:root{--ink:#1a1a18;--dim:#5f5e5a;--line:#d8d6cf;--bg:#fff;--panel:#f5f4ef}
*{box-sizing:border-box}
body{margin:0;background:#e9e8e2;color:var(--ink);
 font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.page{max-width:780px;margin:24px auto;background:var(--bg);padding:32px 40px;
 border:1px solid var(--line)}
h1{font-size:21px;font-weight:600;margin:0 0 2px}
h2{font-size:13px;font-weight:600;margin:26px 0 10px;letter-spacing:.02em;
 text-transform:uppercase;color:var(--dim)}
.sub{color:var(--dim);font-size:13px;margin:0}
.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--dim)}
.row{display:flex;gap:14px;padding:7px 0;border-bottom:1px solid #efeeea}
.row:last-child{border-bottom:0}
.t{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
 color:var(--dim);flex:0 0 62px;padding-top:2px}
.v{flex:1}
.note{color:var(--dim);font-size:13px}
.red{color:var(--dim);font-style:italic}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:4px 0;vertical-align:top}
td.k{color:var(--dim);width:45%}
td.v2{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.box{border:1px solid var(--ink);padding:14px 16px;margin-top:22px}
.box h3{margin:0 0 4px;font-size:15px;font-weight:600}
.bar{position:relative;height:26px;margin:14px 0 6px}
.bar .line{position:absolute;top:8px;left:0;right:0;height:2px;background:var(--ink)}
.bar .cap{position:absolute;top:4px;width:2px;height:10px;background:var(--ink)}
.bar .cap.l{left:0}.bar .cap.r{right:0}
.bar .lb{position:absolute;top:16px;font-size:12px;color:var(--dim)}
.bar .lb.l{left:0}.bar .lb.r{right:0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
 background:var(--panel);padding:2px 5px}
.appendix{page-break-before:always;margin-top:28px;border-top:1px solid var(--line);
 padding-top:20px}
.hash{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;
 word-break:break-all;color:var(--dim)}
@media print{
 body{background:#fff}
 .page{margin:0;max-width:none;border:0;padding:0}
 .box{border:1px solid #000}
 @page{size:A4;margin:16mm}
}
"""

SERVICE_PREFIXES = ("_beacon.", "_redaction.")


def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _ts(ms: Optional[int], fmt: str = "%H:%M") -> str:
    if ms is None:
        return "—"
    return time.strftime(fmt, time.gmtime(ms / 1000))


def _full(ms: Optional[int]) -> str:
    if ms is None:
        return "—"
    return time.strftime("%d.%m.%Y %H:%M UTC", time.gmtime(ms / 1000))


def _fields(rec: dict) -> dict:
    return {f["name"]: f for f in rec["fields"]}


def _is_service(rec: dict) -> Optional[str]:
    for name in _fields(rec):
        for p in SERVICE_PREFIXES:
            if name.startswith(p):
                return p
    return None


def _value(f: dict) -> Optional[str]:
    if "leaf" in f:
        return None
    if "s" in f:
        return f["s"]
    return "(двоичные данные, %d симв. base64)" % len(f.get("b", ""))


def render(manifest: dict, records: List[dict], segment: dict, day: dict,
           anchor_paths: List[str]) -> str:
    body = []
    body.append('<div class="page">')

    seqs = manifest["seqs"]
    body.append("<h1>Отчёт по эпизоду</h1>")
    body.append('<p class="sub">%s · записи %s из %d в отрезке</p>'
                % (_esc(manifest["period_id"]),
                   _esc("–".join(str(s) for s in (seqs[0], seqs[-1]))
                        if len(seqs) > 1 else str(seqs[0])),
                   manifest["disclosed_of_total"][1]))
    body.append('<p class="id">журнал %s · поток %s</p>'
                % (_esc(manifest["realm_id"]), _esc(manifest["stream_id"])))

    # --- что записано ---
    body.append("<h2>Что записано</h2>")
    redactions = []
    for rec in records:
        kind = _is_service(rec)
        fs = _fields(rec)
        if kind == "_redaction.":
            redactions.append(rec)
            continue
        if kind == "_beacon.":
            continue
        lines = []
        for name, f in fs.items():
            if name.startswith("config."):
                continue
            val = _value(f)
            if val is None:
                lines.append('<div class="red">%s — вычеркнуто %s</div>'
                             % (_esc(name),
                                _full(f.get("redacted", {}).get("at"))))
            else:
                lines.append("<div><b>%s</b> %s</div>" % (_esc(name), _esc(val)))
        body.append('<div class="row"><div class="t">%s</div><div class="v">%s</div></div>'
                    % (_ts(rec["ts"]), "".join(lines)))

    for rec in redactions:
        fs = _fields(rec)
        body.append('<div class="row"><div class="t">%s</div><div class="v red">'
                    'Вычеркнуто из записи %s: %s — %s</div></div>'
                    % (_ts(rec["ts"]),
                       _esc(fs.get("_redaction.target_seq", {}).get("s", "?")),
                       _esc(fs.get("_redaction.fields", {}).get("s", "")),
                       _esc(fs.get("_redaction.reason", {}).get("s", ""))))

    # --- настройки ---
    settings = {}
    for rec in records:
        for name, f in _fields(rec).items():
            if name.startswith("config."):
                settings[name] = _value(f)
    if settings:
        body.append("<h2>Настройки на момент эпизода</h2><table>")
        for k, v in sorted(settings.items()):
            body.append('<tr><td class="k">%s</td><td class="v2">%s</td></tr>'
                        % (_esc(k[len("config."):]), _esc(v if v else "—")))
        body.append("</table>")

    # --- граница времени и проверка ---
    b = manifest.get("beacon")
    lower = beacon_mod.lower_bound_ms(int(b["round"]), b["source"]) if b else None
    anchor_names = [os.path.basename(p) for p in anchor_paths]

    body.append('<div class="box">')
    if anchor_names:
        body.append("<h3>Проверьте это сами</h3>")
        body.append('<p class="note">К пакету приложены пломбы: %s. Проверка '
                    "выполняется у вас, без обращения к тому, кто выдал файл, и "
                    "без доступа в интернет.</p>" % _esc(", ".join(anchor_names)))
    else:
        body.append("<h3>Пломба ещё не поставлена</h3>")
        body.append('<p class="note">Записи и цепь сходятся, но суточная отметка '
                    "за этот день ещё не запечатана. До постановки пломбы документ "
                    "не доказывает неизменность.</p>")

    if lower:
        body.append('<div class="bar"><div class="line"></div>'
                    '<div class="cap l"></div><div class="cap r"></div>'
                    '<div class="lb l">не раньше %s</div>'
                    '<div class="lb r">не позже пломбы</div></div>'
                    % _esc(_full(lower)))
        body.append('<p class="note">Нижняя граница — публичный маяк %s, раунд %s: '
                    "его значение нельзя было знать заранее, поэтому запись создана "
                    "после него. Верхнюю границу даёт пломба; точное время выводит "
                    "команда проверки.</p>" % (_esc(b["source"]), _esc(b["round"])))
    else:
        # Шкалу с двумя засечками рисовать нельзя: односторонняя граница —
        # это не интервал, и показывать её интервалом значит переоценивать.
        body.append('<p class="note" style="margin-top:10px">Известна только '
                    "верхняя граница: не позже постановки пломбы. Нижней нет — "
                    "маяк в этот отрезок записан не был.</p>")
    body.append("<p><code>aihash verify &lt;этот файл&gt;</code></p>")
    body.append("</div>")

    body.append('<p class="note" style="margin-top:18px">Документ подтверждает, что '
                "содержимое не менялось после постановки пломбы. Он не подтверждает, "
                "что записи правдивы, что журнал полон и кто именно их написал.</p>")

    # --- приложение для эксперта ---
    body.append('<div class="appendix">')
    body.append("<h2>Приложение: техническая часть</h2><table>")
    rows = [("Формат", manifest["format"]),
            ("Хеш-функция", manifest["hash"]),
            ("Поток", manifest["stream_id"]),
            ("Отрезок", "%s, записи %d–%d, всего %d"
             % (segment["period_id"], segment["first_seq"], segment["last_seq"],
                segment["count"])),
            ("Раскрыто записей", "%d из %d" % tuple(manifest["disclosed_of_total"])),
            ("Пакет собран", _full(manifest["created"]))]
    for k, v in rows:
        body.append('<tr><td class="k">%s</td><td class="v2">%s</td></tr>'
                    % (_esc(k), _esc(v)))
    body.append("</table>")

    body.append("<h2>Отпечатки</h2>")
    for rec in records:
        body.append('<p class="note">запись %d, содержимое</p><p class="hash">%s</p>'
                    % (rec["seq"], _esc(rec["content_root"])))
        body.append('<p class="note">запись %d, звено</p><p class="hash">%s</p>'
                    % (rec["seq"], _esc(rec["link"])))
    for label, val in [("корень отрезка", segment["segment_root"]),
                       ("отметка отрезка", segment["checkpoint"]),
                       ("суточный корень", day["day_root"]),
                       ("суточная отметка — под пломбой", day["day_checkpoint"])]:
        body.append('<p class="note">%s</p><p class="hash">%s</p>'
                    % (_esc(label), _esc(val)))

    body.append("<h2>Как это проверяется</h2>")
    body.append('<p class="note">Отпечаток каждого поля считается из его имени, '
                "соли и значения; листья сортируются по имени и собираются в дерево "
                "(RFC 6962) — его корень и есть отпечаток содержимого. Звено "
                "связывает предыдущее звено, номер, отпечаток содержимого и "
                "заявленное время. Звенья отрезка образуют дерево, отметки отрезков "
                "за сутки — ещё одно; на суточную отметку ставится пломба. "
                "Вычеркнутое поле сохраняет свой лист, поэтому удаление значения "
                "не меняет отпечаток записи и не рвёт цепь.</p>")
    body.append('<p class="note">Локализация расхождения возможна до записи, но не '
                "до поля: отпечаток считается по записи целиком, и по нему нельзя "
                "определить, какое именно поле изменено.</p>")
    body.append("</div></div>")

    return ("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Отчёт по эпизоду — %s</title><style>%s</style></head><body>%s"
            "</body></html>" % (_esc(manifest["stream_id"]), CSS, "".join(body)))
