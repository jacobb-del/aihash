"""Сборка двух верификаторов из одного источника.

    python3 verifier/build.py

На выходе:
  dist/verify.html        один файл, открывается двойным щелчком, работает офлайн
  dist/aihash-verify.js   тот же код + командная строка: node aihash-verify.js x.seal

Источник один намеренно: две реализации проверки неминуемо разъедутся, и
разойдутся они молча.
"""

import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
DIST = os.path.join(HERE, "dist")

CLI = r'''
/* --- командная строка ----------------------------------------------------
 * node aihash-verify.js <файл.seal>
 *
 * Коды возврата:
 *   0 — сходится и запечатано: содержимое доказано
 *   3 — сходится, но пломба не поставлена либо не подтверждена здесь: НЕ доказано
 *   1 — не сходится
 *   2 — файл не прочитан
 *
 * Код 3 объединяет два разных случая намеренно, но словами их различать
 * обязательно: «пломбы нет» вместо «пломба не подтверждена» занижает
 * доказательство исправного журнала. Подпись штампа RFC 3161 это ядро не
 * проверяет никогда, поэтому второй случай здесь — норма, а не редкость.
 */
if (typeof require !== "undefined" && require.main === module) {
  var fs = require("fs");
  var path = process.argv[2];
  if (!path) {
    console.error("использование: node aihash-verify.js <файл.seal>");
    process.exit(2);
  }
  var WORD = { sealed: "matches and is sealed",
               unverified: "matches; a seal is present but not confirmed here",
               open: "matches; no seal",
               broken: "DOES NOT MATCH" };
  var ANCHOR = { ok: "verified", unverified: "not verified", failed: "DOES NOT MATCH" };
  var HOW = {
    rfc3161: "obtain the timestamp authority root certificate from the "
      + "authority itself (not from this bundle) and check the signature: "
      + "openssl ts -verify -digest <daily checkpoint> -in <file.tsr> "
      + "-CAfile <cacert.pem>",
    opentimestamps: "install the client and retry: "
      + "pip install opentimestamps-client"
  };
  function dt(ms) {
    if (!ms) return "—";
    var d = new Date(ms), p = function (n) { return (n < 10 ? "0" : "") + n; };
    return p(d.getUTCDate()) + "." + p(d.getUTCMonth() + 1) + "." + d.getUTCFullYear() +
      " " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + " UTC";
  }
  var bytes;
  try {
    if (fs.statSync(path).isDirectory()) {
      console.error("это каталог журнала, а не пакет .seal.");
      console.error("Здесь проверяются пакеты: общее ядро не работает с");
      console.error("файловой системой — иначе verify.html перестал бы быть");
      console.error("файлом, который можно прочитать целиком.");
      console.error("Журнал проверяют:  aihash-verify <каталог>");
      console.error("               или aihash verify <каталог>");
      process.exit(2);
    }
    bytes = new Uint8Array(fs.readFileSync(path));
  } catch (e) { console.error("не прочитан: " + e.message); process.exit(2); }

  module.exports.aihash.verify(bytes).then(function (r) {
    if (r.status === "broken") {
      console.log("DOES NOT MATCH\n");
      r.problems.forEach(function (p) { console.log("  " + p); });
      console.log("\nThe previous content is not stored and cannot be recovered —");
      console.log("only the fingerprint is kept. Which field was changed cannot be");
      console.log("told from the fingerprint: it covers the record as a whole.");
      process.exit(1);
    }
    var m = r.manifest;
    console.log("Bundle " + require("path").basename(path));
    console.log("  journal " + m.realm_id + ", stream " + m.stream_id +
                ", segment " + m.period_id);
    console.log("  " + m.disclosed_of_total[0] + " of " +
                m.disclosed_of_total[1] + " records in the segment disclosed");
    console.log("");
    r.checks.forEach(function (c) { console.log("  matches: " + c.label); });
    console.log("");
    r.anchors.forEach(function (x) {
      console.log("  seal " + x.type + ": " + ANCHOR[x.status] + " — " + x.detail);
    });
    console.log("");
    console.log("Verdict: " + WORD[r.status] + ".");
    if (r.status === "unverified") {
      console.log("This is not the same as having no seal: a seal was placed");
      console.log("for these days; verifying it was not finished.");
      var seen = {};
      r.anchors.forEach(function (x) {
        if (x.status !== "unverified" || !x.placed || seen[x.type]) return;
        seen[x.type] = 1;
        if (HOW[x.type]) console.log("  " + x.type + ": " + HOW[x.type]);
      });
    }
    if (r.lower) {
      console.log("The record existed no earlier than " + dt(r.lower) + " (" + r.lowerSource + ")");
      console.log("and no later than the seal.");
    }
    process.exit(r.status === "sealed" ? 0 : 3);
  }).catch(function (e) {
    console.error("не прочитан: " + (e.message || e));
    process.exit(2);
  });
}
'''


def main():
    os.makedirs(DIST, exist_ok=True)
    with open(os.path.join(SRC, "verifier.js"), encoding="utf-8") as f:
        js = f.read()
    with open(os.path.join(SRC, "verify.html.tmpl"), encoding="utf-8") as f:
        html = f.read()

    if "/*__VERIFIER__*/" not in html:
        raise SystemExit("в шаблоне нет метки /*__VERIFIER__*/")
    page = html.replace("/*__VERIFIER__*/", js)

    for pat in (r"<script\s+src=", r"<link\s", r"@import", r"https?://"):
        if re.search(pat, page):
            raise SystemExit("страница ссылается наружу (%s) — она обязана быть "
                             "самодостаточной" % pat)

    out_html = os.path.join(DIST, "verify.html")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(page)

    out_js = os.path.join(DIST, "aihash-verify.js")
    with open(out_js, "w", encoding="utf-8") as f:
        f.write(js + CLI)

    assets = os.path.join(HERE, "..", "python", "aihash", "assets")
    os.makedirs(assets, exist_ok=True)
    with open(os.path.join(assets, "verify.html"), "w", encoding="utf-8") as f:
        f.write(page)

    # Страница в примере обновляется отсюда же, а не живёт отдельной копией:
    # demo/ коммитится ради человека, который скачал репозиторий и хочет
    # потрогать руками, и устаревший верификатор там — ловушка, а не пример.
    demo = os.path.join(HERE, "..", "demo")
    if os.path.isdir(demo):
        with open(os.path.join(demo, "verify.html"), "w", encoding="utf-8") as f:
            f.write(page)

    print("собрано:")
    print("  %s (%d КБ)" % (out_html, os.path.getsize(out_html) // 1024))
    print("  %s (%d КБ)" % (out_js, os.path.getsize(out_js) // 1024))
    print("  копии страницы уложены в python/aihash/assets/ и demo/")


if __name__ == "__main__":
    main()
