/**
 * Проверка журнала и пакета доказательства.
 *
 * Сеть не используется. Наши серверы не используются.
 * Состояний не два: сегодняшняя запись ещё не запечатана, и бинарное
 * «сходится / не сходится» на ней соврало бы.
 *
 * UNVERIFIED и OPEN путать нельзя. Разбора CMS здесь нет, поэтому подпись
 * штампа RFC 3161 не проверяется никогда — и объявлять из-за этого «не
 * запечатано» значит занижать доказательство исправного журнала.
 */

import { readFileSync } from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";

import * as core from "./core.js";
import * as store from "./store.js";
import { verifyAnchorBlob, ANCHOR_FAILED, ANCHOR_OK, ANCHOR_UNVERIFIED,
         type AnchorResult } from "./seal.js";
import { readZip } from "./zip.js";
import { lowerBoundMs } from "./beacon.js";
import type { Manifest } from "./bundle.js";

export const SEALED = "sealed";
export const UNVERIFIED = "unverified";
export const OPEN = "open";
export const BROKEN = "broken";

/**
 * Свести пломбы одних суток в один из трёх исходов.
 *
 * Граница между «пломбы нет» и «пломба не подтверждена» проходит по тому,
 * поставлена ли пломба вообще, а не по тому, удалось ли её проверить.
 */
export function dayStatus(anchors: AnchorResult[]): string {
  let status = OPEN;
  for (const a of anchors) {
    if (a.status === ANCHOR_OK) return SEALED;
    if (a.status === ANCHOR_UNVERIFIED && a.placed) status = UNVERIFIED;
  }
  return status;
}

export interface Check { label: string; ok: boolean }

export interface Result {
  status: string;
  kind: "journal" | "bundle";
  checks: Check[];
  anchors: AnchorResult[];
  problems: string[];
  records: number;
  redacted: number;
  realmId?: string;
  streamId?: string;
  periodId?: string;
  disclosed?: [number, number];
  sealedDays: string[];
  /** Сутки, за которые пломба поставлена, но подтвердить её здесь нечем.
   *  Отдельно от openDays: смешивать их значит занижать доказательство. */
  unverifiedDays: string[];
  openDays: string[];
  lowerMs?: number | null;
  lowerSource?: string | null;
}

function blank(kind: "journal" | "bundle"): Result {
  return { status: BROKEN, kind, checks: [], anchors: [], problems: [],
           records: 0, redacted: 0, sealedDays: [], unverifiedDays: [],
           openDays: [] };
}

function ok(r: Result, label: string, cond: boolean, detail = ""): boolean {
  r.checks.push({ label, ok: cond });
  if (!cond) r.problems.push(detail ? `${label}: ${detail}` : label);
  return cond;
}

export function verifyJournal(root: string): Result {
  const r = blank("journal");
  const layout = new store.Layout(root);
  if (!store.exists(layout.realmFile)) {
    r.problems.push("нет realm.json — каталог не является журналом aihash");
    return r;
  }
  const realm = layout.realm();
  r.realmId = realm.realm_id;
  if (!ok(r, "версия формата", realm.format === core.FORMAT_VERSION, realm.format)) return r;
  if (!ok(r, "хеш-функция", realm.hash === core.HASH_NAME, realm.hash)) return r;

  for (const streamId of layout.streams()) {
    // Звенья нужны только внутри проверки потока: удерживать их здесь
    // значило бы держать в памяти весь журнал без всякой пользы.
    verifyStream(layout, streamId, r);
    if (r.problems.length) return r;
  }

  let prevExpected: Buffer = core.ZERO32;
  const sealedDates = new Set<string>();
  for (const date of layout.dates()) {
    const day = layout.readDay(date)!;
    sealedDates.add(date);
    if (!verifyDay(layout, realm.realm_id, date, day, prevExpected, r)) return r;
    prevExpected = Buffer.from(day.day_checkpoint, "hex");
  }
  for (const s of layout.streams()) {
    for (const p of layout.periods(s)) {
      if (!sealedDates.has(p) && !r.openDays.includes(p)) r.openDays.push(p);
    }
  }
  r.openDays.sort();

  if (r.problems.length) return r;
  r.status = r.sealedDays.length ? SEALED
           : r.unverifiedDays.length ? UNVERIFIED : OPEN;
  return r;
}

function verifyStream(layout: store.Layout, streamId: string,
                      r: Result): Map<number, Buffer> {
  const out = new Map<number, Buffer>();
  let prev: Buffer = core.genesis(streamId);
  let expect = 1;

  for (const period of layout.periods(streamId)) {
    const linkBefore = prev;
    const recs = layout.readSegment(streamId, period);
    for (const rec of recs) {
      if (rec.seq !== expect) {
        r.problems.push(`поток ${streamId}, отрезок ${period}: ожидался seq ` +
                        `${expect}, найден ${rec.seq} — пропуск в цепи`);
        return out;
      }
      let croot: Buffer;
      try {
        croot = core.contentRoot(store.fieldsForRoot(rec.fields));
      } catch (e) {
        r.problems.push(`поток ${streamId} seq=${rec.seq}: ${(e as Error).message}`);
        return out;
      }
      prev = core.link(prev, rec.seq, croot, rec.ts);
      if (prev.toString("hex") !== rec.link) {
        r.problems.push(
          `поток ${streamId} seq=${rec.seq}: звено не совпадает с записанным`);
        return out;
      }
      out.set(rec.seq, prev);
      expect++;
      r.records++;
      r.redacted += rec.fields.filter((f) => f.leaf !== undefined).length;
    }

    const ck = layout.readSegmentCkpt(streamId, period);
    if (!ck || !recs.length) continue;
    const segLinks: Buffer[] = [];
    for (let q = recs[0]!.seq; q <= recs[recs.length - 1]!.seq; q++) {
      segLinks.push(out.get(q)!);
    }
    const root = core.segRoot(segLinks);
    if (root.toString("hex") !== ck.segment_root) {
      r.problems.push(`поток ${streamId}, отрезок ${period}: корень не совпадает`);
      return out;
    }
    if (ck.link_before !== linkBefore.toString("hex")) {
      r.problems.push(
        `поток ${streamId}, отрезок ${period}: не связан с предыдущим отрезком`);
      return out;
    }
    const want = core.segCkpt({
      streamId, periodId: period, firstSeq: ck.first_seq, lastSeq: ck.last_seq,
      count: ck.count, linkBefore: Buffer.from(ck.link_before, "hex"),
      linkLast: Buffer.from(ck.link_last, "hex"), root,
      prevCheckpoint: Buffer.from(ck.prev_checkpoint, "hex"),
    });
    if (want.toString("hex") !== ck.checkpoint) {
      r.problems.push(`поток ${streamId}, отрезок ${period}: отметка не совпадает`);
      return out;
    }
  }
  return out;
}

function verifyDay(layout: store.Layout, realmId: string, date: string,
                   day: store.DayCheckpoint, prevExpected: Buffer,
                   r: Result): boolean {
  const ckpts: string[] = [];
  for (const s of day.streams) {
    const seg = layout.readSegmentCkpt(s, date);
    if (!seg) {
      r.problems.push(`сутки ${date}: нет отметки отрезка для потока ${s}`);
      return false;
    }
    ckpts.push(seg.checkpoint);
  }
  if (ckpts.join(",") !== day.segment_checkpoints.join(",")) {
    r.problems.push(`сутки ${date}: перечень отметок отрезков не совпадает`);
    return false;
  }
  const root = core.dayRoot(day.segment_checkpoints.map((c) => Buffer.from(c, "hex")));
  if (root.toString("hex") !== day.day_root) {
    r.problems.push(`сутки ${date}: суточный корень не совпадает`);
    return false;
  }
  const dck = core.dayCkpt(realmId, date, day.streams.length, root,
                           Buffer.from(day.prev_checkpoint, "hex"));
  if (dck.toString("hex") !== day.day_checkpoint) {
    r.problems.push(`сутки ${date}: суточная отметка не совпадает`);
    return false;
  }
  if (day.prev_checkpoint !== prevExpected.toString("hex")) {
    r.problems.push(`сутки ${date}: не связаны с предыдущими сутками`);
    return false;
  }

  const paths = [...layout.anchorsFor(date)];
  const feed = path.join(layout.anchorsDir(), "feed.jsonl");
  if (store.exists(feed)) paths.push(feed);
  const mine: AnchorResult[] = [];
  for (const p of paths) {
    const res = verifyAnchorBlob(p, readFileSync(p), dck, date);
    res.date = date;
    mine.push(res);
    r.anchors.push(res);
    if (res.status === ANCHOR_FAILED) {
      r.problems.push(`сутки ${date}: пломба ${res.type} не сходится — ${res.detail}`);
      return false;
    }
  }
  const status = dayStatus(mine);
  (status === SEALED ? r.sealedDays
   : status === UNVERIFIED ? r.unverifiedDays : r.openDays).push(date);
  return true;
}

export async function verifyBundle(file: string): Promise<Result> {
  const r = blank("bundle");
  let files: Map<string, Buffer>;
  try {
    files = readZip(await fsp.readFile(file));
  } catch (e) {
    r.problems.push(`не читается как архив: ${(e as Error).message}`);
    return r;
  }
  const need = <T>(name: string): T | null => {
    const b = files.get(name);
    if (!b) { r.problems.push(`в пакете нет ${name}`); return null; }
    try { return JSON.parse(b.toString("utf8")) as T; }
    catch { r.problems.push(`${name} не разбирается`); return null; }
  };

  const manifest = need<Manifest>("manifest.json");
  const proofs = need<any>("proofs.json");
  const seg = need<store.SegmentCheckpoint>("segment.json");
  const day = need<store.DayCheckpoint>("day.json");
  const recBytes = files.get("records.jsonl");
  if (!manifest || !proofs || !seg || !day || !recBytes) {
    if (!recBytes) r.problems.push("в пакете нет records.jsonl");
    return r;
  }
  let records: store.StoredRecord[];
  try {
    records = recBytes.toString("utf8").split("\n")
      .filter((l) => l.trim())
      .map((l, i) => {
        const rec = JSON.parse(l) as store.StoredRecord;
        if (!rec || typeof rec.seq !== "number" || !Array.isArray(rec.fields)) {
          throw new core.FormatError(`records.jsonl строка ${i + 1}: нет seq или полей`);
        }
        return rec;
      });
  } catch (e) {
    r.problems.push((e as Error).message);
    return r;
  }
  if (!records.length) {
    r.problems.push("в пакете нет ни одной раскрытой записи");
    return r;
  }

  r.realmId = manifest.realm_id;
  r.streamId = manifest.stream_id;
  r.periodId = manifest.period_id;
  r.disclosed = manifest.disclosed_of_total;

  if (!ok(r, "версия формата", manifest.format === core.FORMAT_VERSION)) return r;
  if (!ok(r, "хеш-функция", manifest.hash === core.HASH_NAME)) return r;

  for (const rec of records) {
    const p = proofs.records?.[String(rec.seq)];
    if (!ok(r, `запись seq=${rec.seq}: путь в пакете`, !!p)) return r;
    let croot: Buffer;
    try { croot = core.contentRoot(store.fieldsForRoot(rec.fields)); }
    catch (e) {
      ok(r, `запись seq=${rec.seq}: поля`, false, (e as Error).message);
      return r;
    }
    const l = core.link(Buffer.from(p.prev_link, "hex"), rec.seq, croot, rec.ts);
    if (!ok(r, `запись seq=${rec.seq}: содержимое и звено`,
            l.toString("hex") === p.link)) return r;
    const got = core.applyPath(core.segLeaf(l), p.segment_path);
    if (!ok(r, `запись seq=${rec.seq}: путь до корня отрезка`,
            got.toString("hex") === seg.segment_root)) return r;
  }

  let ck: Buffer;
  try {
    ck = core.segCkpt({
      streamId: seg.stream_id, periodId: seg.period_id, firstSeq: seg.first_seq,
      lastSeq: seg.last_seq, count: seg.count,
      linkBefore: Buffer.from(seg.link_before, "hex"),
      linkLast: Buffer.from(seg.link_last, "hex"),
      root: Buffer.from(seg.segment_root, "hex"),
      prevCheckpoint: Buffer.from(seg.prev_checkpoint, "hex"),
    });
  } catch (e) {
    ok(r, "отметка отрезка", false, (e as Error).message);
    return r;
  }
  if (!ok(r, "отметка отрезка", ck.toString("hex") === seg.checkpoint)) return r;

  const droot = core.applyPath(core.dayLeaf(ck), proofs.day_path);
  if (!ok(r, "путь до суточного корня", droot.toString("hex") === day.day_root)) return r;

  const dck = core.dayCkpt(day.realm_id, day.date, day.streams.length,
                           Buffer.from(day.day_root, "hex"),
                           Buffer.from(day.prev_checkpoint, "hex"));
  if (!ok(r, "суточная отметка", dck.toString("hex") === day.day_checkpoint)) return r;

  for (const name of [...files.keys()].filter((n) => n.startsWith("anchors/")).sort()) {
    const res = verifyAnchorBlob(name, files.get(name)!, dck, day.date);
    r.anchors.push(res);
    if (res.status === ANCHOR_FAILED) {
      r.problems.push(`пломба ${res.type}: ${res.detail}`);
    }
  }
  if (r.problems.length) return r;

  r.records = records.length;
  if (manifest.beacon) {
    r.lowerMs = lowerBoundMs(Number(manifest.beacon.round), manifest.beacon.source);
    r.lowerSource = `${manifest.beacon.source} раунд ${manifest.beacon.round}`;
  }
  r.status = dayStatus(r.anchors);
  return r;
}
