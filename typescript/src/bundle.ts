/**
 * Пакет доказательства .seal и выписка на одну страницу.
 *
 * Пакет самодостаточен: проверка не требует сети, наших серверов, установки
 * чего-либо и учётной записи. Раскрывается только то, что положили в пакет —
 * остальные записи журнала в нём отсутствуют и по нему невосстановимы.
 */

import * as fsp from "node:fs/promises";
import * as path from "node:path";

import * as core from "./core.js";
import * as store from "./store.js";
import { segmentLinks } from "./seal.js";
import { writeZip } from "./zip.js";
import { lowerBoundMs } from "./beacon.js";

export interface Manifest {
  format: string;
  hash: string;
  realm_id: string;
  stream_id: string;
  period_id: string;
  seqs: number[];
  created: number;
  beacon: { source: string; round: string; seq: number } | null;
  disclosed_of_total: [number, number];
}

const VERIFY_TXT = (name: string) => `Как проверить этот файл

Это пакет доказательства формата aihash/1. Он подтверждает, что перечисленные
в нём записи существовали в указанный промежуток времени и с тех пор не
менялись.

Проверка выполняется у вас, без обращения к тому, кто выдал этот файл, и без
доступа в интернет:

    aihash-verify ${name}

либо, если ставить ничего не хотите, откройте verify.html из этого архива
двойным щелчком и перетащите в неё этот же файл.

ВАЖНО. Verify.html лежит здесь для удобства, но приложила его сторона, которая
этот файл выдала. Если спор острый, возьмите verify.html из открытого проекта
и сверьте его отпечаток. Верификатор, полученный от оппонента, — не
независимая проверка.

Пакет намеренно собран без сжатия: чтобы верификатору не требовался
распаковщик и он оставался читаемым целиком.

Чего пакет НЕ доказывает: что записи правдивы, что журнал полон, и кто именно
их написал. Он доказывает, что содержимое не менялось после постановки пломбы
и что оно существовало в указанном промежутке.
`;

function periodOfSeq(layout: store.Layout, streamId: string, seq: number): string {
  for (const p of layout.periods(streamId)) {
    const recs = layout.readSegment(streamId, p);
    if (recs.length && recs[0]!.seq <= seq && seq <= recs[recs.length - 1]!.seq) {
      return p;
    }
  }
  throw new core.FormatError(`запись seq=${seq} не найдена в потоке ${streamId}`);
}

function beaconOf(recs: store.StoredRecord[]): Manifest["beacon"] {
  for (const rec of recs) {
    const byName = new Map(rec.fields.map((f) => [f.name, f]));
    const round = byName.get("_beacon.round");
    if (round?.s !== undefined) {
      return { source: byName.get("_beacon.source")?.s ?? "", round: round.s,
               seq: rec.seq };
    }
  }
  return null;
}

export async function build(root: string, streamId: string, seqs: number[],
                            outPath: string,
                            opts: { feedPath?: string; verifierPage?: string } = {}):
    Promise<string> {
  const layout = new store.Layout(root);
  const realm = layout.realm();
  const wanted = [...new Set(seqs)].sort((a, b) => a - b);

  const period = periodOfSeq(layout, streamId, wanted[0]!);
  for (const s of wanted) {
    if (periodOfSeq(layout, streamId, s) !== period) {
      throw new core.FormatError(
        "записи лежат в разных отрезках — соберите отдельные пакеты");
    }
  }

  const seg = layout.readSegmentCkpt(streamId, period);
  if (!seg) {
    throw new core.FormatError(`отрезок ${period} ещё не закрыт`);
  }
  const day = layout.readDay(period);
  if (!day) throw new core.FormatError(`сутки ${period} не закрыты`);

  const recs = layout.readSegment(streamId, period);
  const bySeq = new Map(recs.map((r) => [r.seq, r]));
  const missing = wanted.filter((s) => !bySeq.has(s));
  if (missing.length) {
    throw new core.FormatError(`нет записей: ${missing.join(", ")}`);
  }

  // Начало — link_before из уже запечатанной отметки. Сходимость проверяется
  // тем, что пересчитанный корень отрезка совпадает с запечатанным.
  const computed = segmentLinks(layout, streamId, period, recs,
                                Buffer.from(seg.link_before, "hex"));
  const links = new Map(recs.map((r, i) => [r.seq, computed[i]!]));
  const segLeaves = computed.map(core.segLeaf);
  if (core.mth(segLeaves).toString("hex") !== seg.segment_root) {
    throw new core.FormatError(
      `поток ${streamId}, отрезок ${period}: пересчитанный корень не совпадает ` +
      "с запечатанным — пакет не собран");
  }
  const indexOf = new Map(recs.map((r, i) => [r.seq, i]));

  const proofs = {
    records: {} as Record<string, {
      prev_link: string; link: string; leaf_index: number;
      segment_path: core.PathStep[];
    }>,
    day_path: [] as core.PathStep[],
  };
  for (const s of wanted) {
    const prev = links.get(s - 1) ?? Buffer.from(seg.link_before, "hex");
    proofs.records[String(s)] = {
      prev_link: prev.toString("hex"),
      link: links.get(s)!.toString("hex"),
      leaf_index: indexOf.get(s)!,
      segment_path: core.auditPath(indexOf.get(s)!, segLeaves),
    };
  }

  const ckpts = day.segment_checkpoints.map((c) => Buffer.from(c, "hex"));
  proofs.day_path = core.auditPath(day.streams.indexOf(streamId),
                                   ckpts.map(core.dayLeaf));

  const manifest: Manifest = {
    format: core.FORMAT_VERSION, hash: core.HASH_NAME, realm_id: realm.realm_id,
    stream_id: streamId, period_id: period, seqs: wanted, created: Date.now(),
    beacon: beaconOf(recs), disclosed_of_total: [wanted.length, seg.count],
  };

  const anchorPaths = [...layout.anchorsFor(period)];
  const feed = opts.feedPath ?? path.join(layout.anchorsDir(), "feed.jsonl");
  if (store.exists(feed)) anchorPaths.push(feed);

  const disclosed = wanted.map((s) => bySeq.get(s)!);
  const entries = [
    { name: "manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 2)) },
    { name: "records.jsonl",
      data: Buffer.from(disclosed.map(store.recordLine).join("\n") + "\n") },
    { name: "proofs.json", data: Buffer.from(JSON.stringify(proofs, null, 2)) },
    { name: "segment.json", data: Buffer.from(JSON.stringify(seg, null, 2)) },
    { name: "day.json", data: Buffer.from(JSON.stringify(day, null, 2)) },
  ];
  for (const p of anchorPaths) {
    entries.push({ name: "anchors/" + path.basename(p),
                   data: await fsp.readFile(p) });
  }
  entries.push({ name: "report.html",
                 data: Buffer.from(renderReport(manifest, disclosed, seg, day,
                                                anchorPaths.map((p) => path.basename(p)))) });
  if (opts.verifierPage && store.exists(opts.verifierPage)) {
    entries.push({ name: "verify.html", data: await fsp.readFile(opts.verifierPage) });
  }
  entries.push({ name: "VERIFY.txt",
                 data: Buffer.from(VERIFY_TXT(path.basename(outPath))) });

  await fsp.mkdir(path.dirname(path.resolve(outPath)), { recursive: true });
  await fsp.writeFile(outPath, writeZip(entries));
  return outPath;
}

// --- выписка ----------------------------------------------------------------

const CSS = `
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
.id{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--dim)}
.row{display:flex;gap:14px;padding:7px 0;border-bottom:1px solid #efeeea}
.row:last-child{border-bottom:0}
.t{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--dim);
 flex:0 0 62px;padding-top:2px}
.v{flex:1}
.note{color:var(--dim);font-size:13px}
.red{color:var(--dim);font-style:italic}
table{width:100%;border-collapse:collapse;font-size:13px}
td{padding:4px 0;vertical-align:top}
td.k{color:var(--dim);width:45%}
td.v2{text-align:right;font-family:ui-monospace,Menlo,monospace;font-size:12px}
.box{border:1px solid var(--ink);padding:14px 16px;margin-top:22px}
.box h3{margin:0 0 4px;font-size:15px;font-weight:600}
.bar{position:relative;height:26px;margin:14px 0 6px}
.bar .line{position:absolute;top:8px;left:0;right:0;height:2px;background:var(--ink)}
.bar .cap{position:absolute;top:4px;width:2px;height:10px;background:var(--ink)}
.bar .cap.l{left:0}.bar .cap.r{right:0}
.bar .lb{position:absolute;top:16px;font-size:12px;color:var(--dim)}
.bar .lb.l{left:0}.bar .lb.r{right:0}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;background:var(--panel);
 padding:2px 5px}
.appendix{page-break-before:always;margin-top:28px;border-top:1px solid var(--line);
 padding-top:20px}
.hash{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all;
 color:var(--dim)}
@media print{body{background:#fff}.page{margin:0;max-width:none;border:0;padding:0}
 .box{border:1px solid #000}@page{size:A4;margin:16mm}}
`;

const esc = (s: unknown) =>
  String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] ?? c));

function hm(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}`;
}

function full(ms: number | null): string {
  if (!ms) return "—";
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}.${d.getUTCFullYear()} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

function valueOf(f: store.StoredField): string | null {
  if (f.leaf !== undefined) return null;
  if (f.s !== undefined) return f.s;
  return `(двоичные данные, ${(f.b ?? "").length} симв. base64)`;
}

/**
 * Правила из плана: время показывается интервалом, а не точкой; записанное
 * отделено от выведенного; вычёркивание — строка в хронологии; документ
 * двухслойный; печать важнее экрана.
 *
 * Выписку составляет тот, кто её предъявляет, поэтому она НЕ утверждает, что
 * проверка пройдена. Зелёную галочку ставит читатель у себя.
 */
export function renderReport(manifest: Manifest, records: store.StoredRecord[],
                             seg: store.SegmentCheckpoint, day: store.DayCheckpoint,
                             anchorNames: string[]): string {
  const b: string[] = ['<div class="page">'];
  const seqs = manifest.seqs;
  b.push("<h1>Отчёт по эпизоду</h1>");
  b.push(`<p class="sub">${esc(manifest.period_id)} · записи ` +
         `${esc(seqs.length > 1 ? `${seqs[0]}–${seqs[seqs.length - 1]}` : seqs[0])} ` +
         `из ${manifest.disclosed_of_total[1]} в отрезке</p>`);
  b.push(`<p class="id">журнал ${esc(manifest.realm_id)} · поток ` +
         `${esc(manifest.stream_id)}</p>`);

  b.push("<h2>Что записано</h2>");
  const redactions: store.StoredRecord[] = [];
  const settings = new Map<string, string>();
  for (const rec of records) {
    const names = rec.fields.map((f) => f.name);
    if (names.some((n) => n.startsWith("_redaction."))) {
      redactions.push(rec);
      continue;
    }
    if (names.some((n) => n.startsWith("_beacon."))) continue;
    const lines: string[] = [];
    for (const f of rec.fields) {
      if (f.name.startsWith("config.")) {
        settings.set(f.name, valueOf(f) ?? "");
        continue;
      }
      const v = valueOf(f);
      if (v === null) {
        lines.push(`<div class="red">${esc(f.name)} — вычеркнуто ` +
                   `${full(f.redacted?.at ?? null)}</div>`);
      } else {
        lines.push(`<div><b>${esc(f.name)}</b> ${esc(v)}</div>`);
      }
    }
    b.push(`<div class="row"><div class="t">${hm(rec.ts)}</div>` +
           `<div class="v">${lines.join("")}</div></div>`);
  }
  for (const rec of redactions) {
    const m = new Map(rec.fields.map((f) => [f.name, f.s ?? ""]));
    b.push(`<div class="row"><div class="t">${hm(rec.ts)}</div>` +
           `<div class="v red">Вычеркнуто из записи ` +
           `${esc(m.get("_redaction.target_seq"))}: ` +
           `${esc(m.get("_redaction.fields"))} — ` +
           `${esc(m.get("_redaction.reason"))}</div></div>`);
  }

  if (settings.size) {
    b.push("<h2>Настройки на момент эпизода</h2><table>");
    for (const k of [...settings.keys()].sort()) {
      b.push(`<tr><td class="k">${esc(k.slice("config.".length))}</td>` +
             `<td class="v2">${esc(settings.get(k) || "—")}</td></tr>`);
    }
    b.push("</table>");
  }

  const lower = manifest.beacon
    ? lowerBoundMs(Number(manifest.beacon.round), manifest.beacon.source)
    : null;

  b.push('<div class="box">');
  if (anchorNames.length) {
    b.push("<h3>Проверьте это сами</h3>");
    b.push('<p class="note">К пакету приложены пломбы: ' +
           `${esc(anchorNames.join(", "))}. Проверка выполняется у вас, без ` +
           "обращения к тому, кто выдал файл, и без доступа в интернет.</p>");
  } else {
    b.push("<h3>Пломба ещё не поставлена</h3>");
    b.push('<p class="note">Записи и цепь сходятся, но суточная отметка за этот ' +
           "день ещё не запечатана. До постановки пломбы документ не доказывает " +
           "неизменность.</p>");
  }
  if (lower) {
    b.push('<div class="bar"><div class="line"></div><div class="cap l"></div>' +
           `<div class="cap r"></div><div class="lb l">не раньше ${esc(full(lower))}` +
           '</div><div class="lb r">не позже пломбы</div></div>');
    b.push(`<p class="note">Нижняя граница — публичный маяк ` +
           `${esc(manifest.beacon!.source)}, раунд ${esc(manifest.beacon!.round)}: ` +
           "его значение нельзя было знать заранее, поэтому запись создана после " +
           "него. Верхнюю границу даёт пломба; точное время выводит команда " +
           "проверки.</p>");
  } else {
    b.push('<p class="note">Известна только верхняя граница: не позже постановки ' +
           "пломбы. Нижней нет — маяк в этот отрезок записан не был.</p>");
  }
  b.push("<p><code>aihash-verify &lt;этот файл&gt;</code></p></div>");

  b.push('<p class="note" style="margin-top:18px">Документ подтверждает, что ' +
         "содержимое не менялось после постановки пломбы. Он не подтверждает, " +
         "что записи правдивы, что журнал полон и кто именно их написал.</p>");

  b.push('<div class="appendix"><h2>Приложение: техническая часть</h2><table>');
  const rows: Array<[string, string]> = [
    ["Формат", manifest.format], ["Хеш-функция", manifest.hash],
    ["Поток", manifest.stream_id],
    ["Отрезок", `${seg.period_id}, записи ${seg.first_seq}–${seg.last_seq}, ` +
                `всего ${seg.count}`],
    ["Раскрыто записей", `${manifest.disclosed_of_total[0]} из ` +
                         `${manifest.disclosed_of_total[1]}`],
    ["Пакет собран", full(manifest.created)],
  ];
  for (const [k, v] of rows) {
    b.push(`<tr><td class="k">${esc(k)}</td><td class="v2">${esc(v)}</td></tr>`);
  }
  b.push("</table><h2>Отпечатки</h2>");
  for (const rec of records) {
    b.push(`<p class="note">запись ${rec.seq}, содержимое</p>` +
           `<p class="hash">${esc(rec.content_root)}</p>`);
    b.push(`<p class="note">запись ${rec.seq}, звено</p>` +
           `<p class="hash">${esc(rec.link)}</p>`);
  }
  for (const [label, val] of [["корень отрезка", seg.segment_root],
                              ["отметка отрезка", seg.checkpoint],
                              ["суточный корень", day.day_root],
                              ["суточная отметка — под пломбой", day.day_checkpoint]]) {
    b.push(`<p class="note">${esc(label)}</p><p class="hash">${esc(val)}</p>`);
  }
  b.push('<h2>Как это проверяется</h2><p class="note">Отпечаток каждого поля ' +
         "считается из его имени, соли и значения; листья сортируются по имени и " +
         "собираются в дерево (RFC 6962) — его корень и есть отпечаток содержимого. " +
         "Звено связывает предыдущее звено, номер, отпечаток содержимого и " +
         "заявленное время. Звенья отрезка образуют дерево, отметки отрезков за " +
         "сутки — ещё одно; на суточную отметку ставится пломба. Вычеркнутое поле " +
         "сохраняет свой лист, поэтому удаление значения не меняет отпечаток " +
         "записи и не рвёт цепь.</p>");
  b.push('<p class="note">Локализация расхождения возможна до записи, но не до ' +
         "поля: отпечаток считается по записи целиком, и по нему нельзя определить, " +
         "какое именно поле изменено.</p></div></div>");

  return `<!doctype html><html lang="ru"><head><meta charset="utf-8">` +
         `<meta name="viewport" content="width=device-width,initial-scale=1">` +
         `<title>Отчёт по эпизоду — ${esc(manifest.stream_id)}</title>` +
         `<style>${CSS}</style></head><body>${b.join("")}</body></html>`;
}
