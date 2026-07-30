/**
 * Раскладка на диске и кодирование записей.
 *
 * Обычные файлы, без базы данных: через семь лет посторонний эксперт должен
 * открыть каталог и понять содержимое без нашей инфраструктуры.
 */

import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as path from "node:path";

import * as core from "./core.js";

export const RECORD_V = 1;

/** Поле записи в том виде, в каком оно лежит в файле. */
export interface StoredField {
  name: string;
  salt?: string;
  s?: string;
  b?: string;
  leaf?: string;
  redacted?: { at: number; seq: number };
}

export interface StoredRecord {
  v: number;
  seq: number;
  ts: number;
  fields: StoredField[];
  content_root: string;
  link: string;
}

export interface SegmentCheckpoint {
  format: string;
  stream_id: string;
  period_id: string;
  first_seq: number;
  last_seq: number;
  count: number;
  link_before: string;
  link_last: string;
  segment_root: string;
  prev_checkpoint: string;
  checkpoint: string;
}

export interface DayCheckpoint {
  format: string;
  realm_id: string;
  date: string;
  streams: string[];
  segment_checkpoints: string[];
  day_root: string;
  prev_checkpoint: string;
  day_checkpoint: string;
}

export type FieldValue = string | Uint8Array;

export function encodeField(name: string, salt: Buffer, value: FieldValue): StoredField {
  const out: StoredField = { name, salt: salt.toString("hex") };
  if (typeof value === "string") out.s = value;
  else if (value instanceof Uint8Array) out.b = Buffer.from(value).toString("base64");
  else throw new core.FormatError(`значение поля ${name} должно быть строкой или байтами`);
  return out;
}

export function rawValue(f: StoredField): Buffer {
  if (f.s !== undefined && f.b !== undefined) {
    throw new core.FormatError(`поле ${f.name}: s и b одновременно`);
  }
  if (f.s !== undefined) return Buffer.from(f.s, "utf8");
  if (f.b !== undefined) return Buffer.from(f.b, "base64");
  throw new core.FormatError(`поле ${f.name}: нет ни s, ни b`);
}

export function fieldsForRoot(fields: StoredField[]): core.LeafInput[] {
  return fields.map((f) => {
    if (f.leaf !== undefined) {
      if (f.salt !== undefined || f.s !== undefined || f.b !== undefined) {
        throw new core.FormatError(
          `вычеркнутое поле ${f.name} сохранило соль или значение`);
      }
      return { name: f.name, leaf: Buffer.from(f.leaf, "hex") };
    }
    if (f.salt === undefined) throw new core.FormatError(`поле ${f.name}: нет соли`);
    return { name: f.name, salt: Buffer.from(f.salt, "hex"), value: rawValue(f) };
  });
}

export function recordLine(rec: StoredRecord): string {
  return JSON.stringify(rec);
}

// --- атомарная запись -------------------------------------------------------

export async function writeJson(file: string, obj: unknown): Promise<void> {
  const tmp = `${file}.tmp`;
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const fh = await fsp.open(tmp, "w");
  try {
    await fh.writeFile(JSON.stringify(obj, null, 2) + "\n", "utf8");
    await fh.sync();
  } finally {
    await fh.close();
  }
  await fsp.rename(tmp, file);
}

export function readJsonSync<T>(file: string): T {
  return JSON.parse(fs.readFileSync(file, "utf8")) as T;
}

export function exists(file: string): boolean {
  return fs.existsSync(file);
}

// --- раскладка --------------------------------------------------------------

export class Layout {
  readonly root: string;

  constructor(root: string) {
    this.root = path.resolve(root);
  }

  get realmFile(): string {
    return path.join(this.root, "realm.json");
  }

  streamDir(id: string): string {
    return path.join(this.root, "streams", id);
  }

  metaFile(id: string): string {
    return path.join(this.streamDir(id), "meta.json");
  }

  segmentsDir(id: string): string {
    return path.join(this.streamDir(id), "segments");
  }

  segmentFile(id: string, period: string): string {
    return path.join(this.segmentsDir(id), `${period}.jsonl`);
  }

  segmentCkptFile(id: string, period: string): string {
    return path.join(this.segmentsDir(id), `${period}.seg.json`);
  }

  dayFile(date: string): string {
    return path.join(this.root, "days", `${date}.day.json`);
  }

  anchorsDir(): string {
    return path.join(this.root, "anchors");
  }

  anchorFile(date: string, kind: string, ext: string): string {
    return path.join(this.anchorsDir(), `${date}.${kind}.${ext}`);
  }

  streams(): string[] {
    const d = path.join(this.root, "streams");
    if (!fs.existsSync(d)) return [];
    return fs.readdirSync(d, { withFileTypes: true })
      .filter((e) => e.isDirectory()).map((e) => e.name).sort();
  }

  periods(id: string): string[] {
    const d = this.segmentsDir(id);
    if (!fs.existsSync(d)) return [];
    return fs.readdirSync(d).filter((n) => n.endsWith(".jsonl"))
      .map((n) => n.slice(0, -6)).sort();
  }

  dates(): string[] {
    const d = path.join(this.root, "days");
    if (!fs.existsSync(d)) return [];
    return fs.readdirSync(d).filter((n) => n.endsWith(".day.json"))
      .map((n) => n.slice(0, -9)).sort();
  }

  anchorsFor(date: string): string[] {
    const d = this.anchorsDir();
    if (!fs.existsSync(d)) return [];
    return fs.readdirSync(d).filter((n) => n.startsWith(`${date}.`))
      .map((n) => path.join(d, n)).sort();
  }

  readSegment(id: string, period: string): StoredRecord[] {
    const file = this.segmentFile(id, period);
    if (!fs.existsSync(file)) return [];
    const out: StoredRecord[] = [];
    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines.forEach((line, i) => {
      if (!line.trim()) return;
      try {
        out.push(JSON.parse(line) as StoredRecord);
      } catch (e) {
        throw new core.FormatError(`${file} строка ${i + 1}: не разбирается как JSON`);
      }
    });
    return out;
  }

  /**
   * Последняя запись отрезка без чтения всего файла.
   *
   * Пишущему нужен только кончик цепи. Читать ради него весь журнал — значит
   * превращать запуск процесса в минуты на журнале за несколько лет. Проверка
   * цепи целиком — работа верификатора, а не писателя.
   */
  readSegmentTail(id: string, period: string): StoredRecord | null {
    const file = this.segmentFile(id, period);
    if (!fs.existsSync(file)) return null;
    const size = fs.statSync(file).size;
    if (size === 0) return null;
    let window = 1 << 16;
    for (;;) {
      const fd = fs.openSync(file, "r");
      const start = Math.max(0, size - window);
      const buf = Buffer.alloc(size - start);
      try {
        fs.readSync(fd, buf, 0, buf.length, start);
      } finally {
        fs.closeSync(fd);
      }
      if (buf[buf.length - 1] !== 0x0a) {
        throw new core.FormatError(
          `${file}: последняя строка оборвана — процесс упал посреди записи. ` +
          "Обрежьте файл до последнего перевода строки; всё до него проверяется " +
          "как обычно.");
      }
      const lines = buf.toString("utf8").split("\n").filter((l) => l.trim());
      if (lines.length) {
        try {
          return JSON.parse(lines[lines.length - 1]!) as StoredRecord;
        } catch {
          // строка обрезана окном — расширяем и пробуем снова
        }
      }
      if (window >= size) {
        throw new core.FormatError(`${file}: последняя запись не разбирается`);
      }
      window = Math.min(window * 8, size);
    }
  }

  readSegmentCkpt(id: string, period: string): SegmentCheckpoint | null {
    const f = this.segmentCkptFile(id, period);
    return fs.existsSync(f) ? readJsonSync<SegmentCheckpoint>(f) : null;
  }

  readDay(date: string): DayCheckpoint | null {
    const f = this.dayFile(date);
    return fs.existsSync(f) ? readJsonSync<DayCheckpoint>(f) : null;
  }

  realm(): { format: string; hash: string; realm_id: string; created: number } {
    return readJsonSync(this.realmFile);
  }
}

export async function initRealm(layout: Layout, realmId: string,
                                now: number): Promise<void> {
  core.checkId(realmId, "realm_id");
  await fsp.mkdir(path.join(layout.root, "streams"), { recursive: true });
  await fsp.mkdir(path.join(layout.root, "days"), { recursive: true });
  await fsp.mkdir(layout.anchorsDir(), { recursive: true });
  if (fs.existsSync(layout.realmFile)) {
    const existing = layout.realm();
    if (existing.realm_id !== realmId) {
      throw new core.FormatError(
        `каталог принадлежит установке ${existing.realm_id}, а не ${realmId}`);
    }
    return;
  }
  await writeJson(layout.realmFile, {
    format: core.FORMAT_VERSION, hash: core.HASH_NAME,
    realm_id: realmId, created: now,
  });
}

export async function initStream(layout: Layout, streamId: string,
                                 now: number): Promise<void> {
  core.checkId(streamId, "stream_id");
  await fsp.mkdir(layout.segmentsDir(streamId), { recursive: true });
  const file = layout.metaFile(streamId);
  if (fs.existsSync(file)) return;
  await writeJson(file, {
    format: core.FORMAT_VERSION, stream_id: streamId,
    genesis: core.genesis(streamId).toString("hex"), created: now,
  });
}

export function periodOf(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}
