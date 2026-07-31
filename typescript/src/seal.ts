/**
 * Закрытие отрезков, суточная отметка, постановка пломбы.
 *
 * Пломба ставится в трёх местах сразу: типы отвечают разным аудиториям, и их
 * отказы не коррелируют. Пломба считается поставленной при успехе хотя бы
 * одного типа; выписка честно перечисляет сработавшие.
 */

import * as fsp from "node:fs/promises";
import * as path from "node:path";

import * as core from "./core.js";
import * as store from "./store.js";

export const ANCHOR_OK = "ok";
export const ANCHOR_UNVERIFIED = "unverified";
export const ANCHOR_FAILED = "failed";

export interface AnchorResult {
  type: string;
  status: string;
  detail: string;
  date?: string;
  /** Установлено ли, что пломба поставлена именно на эту отметку, — вопрос,
   *  отдельный от «удалось ли её проверить». Без этого разделения «не
   *  проверена» сливает отсутствие пломбы с неоконченной проверкой, а это
   *  разные ответы.
   *
   *  Планка намеренно высокая: признак ставится там, где принадлежность пломбы
   *  отметке доказана, а не там, где в каталоге просто лежит подходяще
   *  названный файл. Иначе любой файл в anchors/ смягчал бы вердикт.
   *  Проставляется в verifyAnchorBlob, поэтому здесь необязательное. */
  placed?: boolean;
}

function guardCurrent(period: string, allowOpen: boolean): void {
  if (allowOpen) return;
  const today = store.periodOf(Date.now());
  if (period >= today) {
    throw new core.FormatError(
      `сутки ${period} ещё идут — закрывать можно только завершившиеся; ` +
      "запечатанный отрезок больше не принимает записи");
  }
}

function prevSegmentCkpt(layout: store.Layout, streamId: string,
                         period: string): Buffer {
  const earlier = layout.periods(streamId).filter((p) => p < period).reverse();
  for (const p of earlier) {
    const ck = layout.readSegmentCkpt(streamId, p);
    if (ck) return Buffer.from(ck.checkpoint, "hex");
  }
  return core.ZERO32;
}

/**
 * Звено, предшествующее отрезку. Берётся из отметки предыдущего отрезка, а не
 * перечитыванием его записей: отметка уже запечатана.
 */
function linkBefore(layout: store.Layout, streamId: string, period: string): Buffer {
  const earlier = layout.periods(streamId).filter((p) => p < period).reverse();
  for (const p of earlier) {
    const ck = layout.readSegmentCkpt(streamId, p);
    if (ck) return Buffer.from(ck.link_last, "hex");
    const tip = layout.readSegmentTail(streamId, p);
    if (tip) return Buffer.from(tip.link, "hex");
  }
  return core.genesis(streamId);
}

/**
 * Пересчитывает звенья ОТРЕЗКА, а не всего журнала.
 *
 * Начало берётся из отметки предыдущего отрезка. Пересчёт от начала времён
 * давал бы то же самое, но стоил бы чтения всего журнала на каждое закрытие
 * суток и на каждую сборку пакета.
 */
export function segmentLinks(layout: store.Layout, streamId: string, period: string,
                             recs: store.StoredRecord[], start: Buffer): Buffer[] {
  const links: Buffer[] = [];
  let prev = start;
  for (const rec of recs) {
    const croot = core.contentRoot(store.fieldsForRoot(rec.fields));
    if (croot.toString("hex") !== rec.content_root) {
      throw new core.FormatError(
        `${streamId} ${period} seq=${rec.seq}: содержимое не совпадает с отпечатком`);
    }
    prev = core.link(prev, rec.seq, croot, rec.ts);
    if (prev.toString("hex") !== rec.link) {
      throw new core.FormatError(
        `${streamId} ${period} seq=${rec.seq}: звено не совпадает с записанным`);
    }
    links.push(prev);
  }
  return links;
}

export async function sealSegment(layout: store.Layout, streamId: string,
                                  period: string, allowOpen = false):
    Promise<store.SegmentCheckpoint | null> {
  guardCurrent(period, allowOpen);
  const recs = layout.readSegment(streamId, period);
  if (!recs.length) return null;

  const first = recs[0]!.seq;
  const last = recs[recs.length - 1]!.seq;
  const lb = linkBefore(layout, streamId, period);
  const segLinks = segmentLinks(layout, streamId, period, recs, lb);

  const root = core.segRoot(segLinks);
  const prev = prevSegmentCkpt(layout, streamId, period);
  const ck = core.segCkpt({
    streamId, periodId: period, firstSeq: first, lastSeq: last,
    count: recs.length, linkBefore: lb, linkLast: segLinks[segLinks.length - 1]!,
    root, prevCheckpoint: prev,
  });

  const obj: store.SegmentCheckpoint = {
    format: core.FORMAT_VERSION, stream_id: streamId, period_id: period,
    first_seq: first, last_seq: last, count: recs.length,
    link_before: lb.toString("hex"),
    link_last: segLinks[segLinks.length - 1]!.toString("hex"),
    segment_root: root.toString("hex"),
    prev_checkpoint: prev.toString("hex"),
    checkpoint: ck.toString("hex"),
  };
  await store.writeJson(layout.segmentCkptFile(streamId, period), obj);
  return obj;
}

function prevDayCkpt(layout: store.Layout, date: string): Buffer {
  for (const d of layout.dates().filter((x) => x < date).reverse()) {
    const day = layout.readDay(d);
    if (day) return Buffer.from(day.day_checkpoint, "hex");
  }
  return core.ZERO32;
}

export async function sealDay(layout: store.Layout, realmId: string, date: string,
                              allowOpen = false): Promise<store.DayCheckpoint | null> {
  guardCurrent(date, allowOpen);
  const pairs: Array<{ stream: string; ckpt: Buffer }> = [];
  for (const streamId of layout.streams()) {
    if (!layout.periods(streamId).includes(date)) continue;
    const seg = layout.readSegmentCkpt(streamId, date)
      ?? (await sealSegment(layout, streamId, date, true));
    if (!seg) continue;
    pairs.push({ stream: streamId, ckpt: Buffer.from(seg.checkpoint, "hex") });
  }
  if (!pairs.length) return null;

  pairs.sort((a, b) =>
    Buffer.compare(Buffer.from(a.stream, "utf8"), Buffer.from(b.stream, "utf8")));
  const ckpts = pairs.map((p) => p.ckpt);
  const root = core.dayRoot(ckpts);
  const prev = prevDayCkpt(layout, date);
  const ck = core.dayCkpt(realmId, date, ckpts.length, root, prev);

  const obj: store.DayCheckpoint = {
    format: core.FORMAT_VERSION, realm_id: realmId, date,
    streams: pairs.map((p) => p.stream),
    segment_checkpoints: ckpts.map((c) => c.toString("hex")),
    day_root: root.toString("hex"),
    prev_checkpoint: prev.toString("hex"),
    day_checkpoint: ck.toString("hex"),
  };
  await store.writeJson(layout.dayFile(date), obj);
  return obj;
}

// --- пломбы -----------------------------------------------------------------

interface FeedEntry {
  seq: number;
  date: string;
  target: string;
  prev: string;
  entry: string;
}

/**
 * Публичная лента с добавлением в конец.
 *
 * Смысл появляется только когда файл публикуется вовне: лента внутри того же
 * каталога, что и журнал, раздвоение не обнаруживает — она под контролем той
 * же стороны.
 */
export async function stampFeed(layout: store.Layout, target: Buffer, date: string,
                                feedPath?: string): Promise<{ path: string;
                                                              published: boolean }> {
  const file = feedPath ?? path.join(layout.anchorsDir(), "feed.jsonl");
  await fsp.mkdir(path.dirname(file), { recursive: true });
  let prev: Buffer = core.ZERO32;
  let seq = 0;
  if (store.exists(file)) {
    const text = await fsp.readFile(file, "utf8");
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      const e = JSON.parse(line) as FeedEntry;
      prev = Buffer.from(e.entry, "hex");
      seq = e.seq;
    }
  }
  const entry = core.H(Buffer.from("aihash/feed/1", "utf8"),
                       core.lp(Buffer.from(date, "utf8")), target, prev);
  const rec: FeedEntry = {
    seq: seq + 1, date, target: target.toString("hex"),
    prev: prev.toString("hex"), entry: entry.toString("hex"),
  };
  const fh = await fsp.open(file, "a");
  try {
    await fh.write(JSON.stringify(rec) + "\n");
    await fh.sync();
  } finally {
    await fh.close();
  }
  return { path: file, published: feedPath !== undefined };
}

/**
 * Проверка публичной ленты. Различаются три исхода, и путать их нельзя:
 *
 *   нет записей за эти сутки       — пломба не поставлена (не подделка)
 *   есть запись, отпечаток другой  — опубликовано другое: ПОДДЕЛКА
 *   две записи с разными отметками — раздвоение журнала: ПОДДЕЛКА
 *
 * Вторая строка — единственное, ради чего лента и заводится. Считая её просто
 * «не запечатано», мы пропустили бы противника, пересчитавшего журнал целиком.
 */
export function verifyFeed(text: string, target: Buffer,
                           date?: string): AnchorResult {
  let prev: Buffer = core.ZERO32;
  let found: FeedEntry | null = null;
  const sameDate: FeedEntry[] = [];
  const lines = text.split("\n").filter((l) => l.trim());
  for (let i = 0; i < lines.length; i++) {
    let e: FeedEntry;
    try {
      e = JSON.parse(lines[i]!) as FeedEntry;
    } catch {
      return { type: "feed", status: ANCHOR_FAILED,
               detail: `feed entry ${i + 1} does not parse` };
    }
    if (e.prev !== prev.toString("hex")) {
      return { type: "feed", status: ANCHOR_FAILED,
               detail: `the feed is broken at entry ${i + 1}` };
    }
    const want = core.H(Buffer.from("aihash/feed/1", "utf8"),
                        core.lp(Buffer.from(e.date, "utf8")),
                        Buffer.from(e.target, "hex"), prev);
    if (want.toString("hex") !== e.entry) {
      return { type: "feed", status: ANCHOR_FAILED,
               detail: `fingerprint of feed entry ${i + 1} does not match` };
    }
    prev = want;
    if (date === undefined || e.date === date) sameDate.push(e);
    if (e.target === target.toString("hex")) found = e;
  }

  const distinct = new Set(sameDate.map((e) => e.target));
  if (distinct.size > 1) {
    return { type: "feed", status: ANCHOR_FAILED,
             detail: `${distinct.size} different checkpoints published in the ` +
                     "feed for these days — the journal was forked" };
  }
  if (found) {
    return { type: "feed", status: ANCHOR_OK, placed: true,
             detail: `entry ${found.seq} in the feed; the strength of this seal ` +
                     "depends on whether the feed is published outside" };
  }
  if (sameDate.length) {
    return { type: "feed", status: ANCHOR_FAILED,
             detail: `a DIFFERENT checkpoint is published in the feed for these ` +
                     `days (${sameDate[0]!.target.slice(0, 16)}…) — the ` +
                     "journal does not match it" };
  }
  // Лента цела, но этих суток в ней нет: пломба не была поставлена. Это
  // «пломбы нет», а не «пломба не подтверждена», поэтому placed остаётся false.
  return { type: "feed", status: ANCHOR_UNVERIFIED, placed: false,
           detail: "the feed is intact but does not contain these days — the " +
                   "feed placed no seal" };
}

/**
 * Проверка пломбы по её байтам, без сети.
 *
 * Типы, которые нельзя подтвердить офлайн без стороннего материала,
 * возвращают «не проверена», а не «в порядке».
 */
export function verifyAnchorBlob(name: string, data: Buffer, target: Buffer,
                                 date?: string): AnchorResult {
  const res = anchorBlob(name, data, target, date);
  if (res.placed === undefined) res.placed = false;
  return res;
}

function anchorBlob(name: string, data: Buffer, target: Buffer,
                    date?: string): AnchorResult {
  const base = path.basename(name);
  if (base === "feed.jsonl") return verifyFeed(data.toString("utf8"), target, date);
  if (base.endsWith(".rfc3161.tsr")) {
    if (!data.includes(target)) {
      return { type: "rfc3161", status: ANCHOR_FAILED,
               detail: "the timestamp was not placed on this daily checkpoint" };
    }
    // Принадлежность штампа отметке доказана сырыми байтами выше: пломба за
    // эти сутки поставлена, вопрос только в подписи.
    return { type: "rfc3161", status: ANCHOR_UNVERIFIED, placed: true,
             detail: "the timestamp covers this checkpoint, but the authority " +
                     "signature was not verified — its certificate is needed: " +
                     "openssl ts -verify" };
  }
  if (base.endsWith(".opentimestamps.ots")) {
    // Разобрать .ots здесь нечем: что это пломба над нашей отметкой — не
    // установлено, поэтому и постановка пломбы не засчитывается.
    return { type: "opentimestamps", status: ANCHOR_UNVERIFIED,
             detail: "the opentimestamps client is required" };
  }
  // Файл в anchors/ есть, а что это — неизвестно. Ни принадлежность отметке,
  // ни сам факт постановки пломбы отсюда не следуют.
  return { type: base, status: ANCHOR_UNVERIFIED,
           detail: "unknown seal type — skipped, and not counted" };
}

export async function anchorDay(layout: store.Layout, date: string,
                                kinds: string[], feedPath?: string):
    Promise<Array<{ type: string; ok: boolean; detail?: string; error?: string }>> {
  const day = layout.readDay(date);
  if (!day) {
    throw new core.FormatError(`сутки ${date} не закрыты — нечего пломбировать`);
  }
  const target = Buffer.from(day.day_checkpoint, "hex");
  const out = [];
  for (const kind of kinds) {
    try {
      if (kind === "feed") {
        const r = await stampFeed(layout, target, date, feedPath);
        out.push({ type: kind, ok: true,
                   detail: r.published ? "" : "лента не опубликована вовне" });
      } else if (kind === "rfc3161") {
        out.push({ type: kind, ok: false,
                   error: "штамп RFC 3161 в версии для Node не реализован — " +
                          "поставьте его командой aihash seal (Python)" });
      } else {
        out.push({ type: kind, ok: false, error: `тип ${kind} не поддерживается` });
      }
    } catch (e) {
      out.push({ type: kind, ok: false, error: (e as Error).message });
    }
  }
  return out;
}
