/**
 * Примитивы формата aihash/1.
 *
 * Нормативный источник — FORMAT.md. При расхождении прав документ.
 * Сходимость с spec/vectors проверяется в test/vectors.test.ts — теми же
 * файлами, по которым проверяются Python, Go и браузерный верификатор.
 *
 * Ни одной внешней зависимости: только node:crypto.
 */

import { createHash, randomBytes } from "node:crypto";

export const FORMAT_VERSION = "aihash/1";
export const HASH_NAME = "sha256";
export const SALT_LEN = 16;
export const ZERO32 = Buffer.alloc(32);

export const TAG_FIELD_LEAF = 0x01;
export const TAG_NODE = 0x02;
export const TAG_LINK = 0x03;
export const TAG_GENESIS = 0x04;
export const TAG_SEG_LEAF = 0x05;
export const TAG_SEG_CKPT = 0x06;
export const TAG_DAY_LEAF = 0x07;
export const TAG_DAY_CKPT = 0x08;

const ID_RE = /^[A-Za-z0-9._:-]+$/;

/** Нарушение спецификации формата. */
export class FormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FormatError";
  }
}

/** LEB128 без знака. Значение не должно превышать 2^53-1. */
export function varint(n: number): Buffer {
  if (!Number.isInteger(n) || n < 0) {
    throw new FormatError("varint: ожидается неотрицательное целое");
  }
  if (n > Number.MAX_SAFE_INTEGER) {
    throw new FormatError("varint: значение вне безопасного диапазона");
  }
  const out: number[] = [];
  for (;;) {
    const b = n % 128;
    n = Math.floor(n / 128);
    if (n) out.push(b | 0x80);
    else {
      out.push(b);
      break;
    }
  }
  return Buffer.from(out);
}

export function lp(b: Buffer): Buffer {
  return Buffer.concat([varint(b.length), b]);
}

export function H(...parts: Buffer[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

export function tag(t: number): Buffer {
  return Buffer.from([t]);
}

export function newSalt(): Buffer {
  return randomBytes(SALT_LEN);
}

export function checkId(value: string, what: string): string {
  const b = Buffer.from(value, "utf8");
  if (b.length < 1 || b.length > 64) {
    throw new FormatError(`${what}: длина вне 1..64 байт`);
  }
  if (!ID_RE.test(value)) {
    throw new FormatError(`${what}: допустимы только A-Z a-z 0-9 . _ : -`);
  }
  // Точка и две точки состоят из разрешённых символов, но выводят запись за
  // пределы отведённого ей каталога.
  if (value.startsWith(".")) {
    throw new FormatError(
      `${what}: имя не может начинаться с точки (${value}) — ` +
      "оно становится именем каталога");
  }
  return value;
}

export function checkFieldName(name: string): Buffer {
  const nb = Buffer.from(name, "utf8");
  if (nb.length < 1 || nb.length > 255) {
    throw new FormatError(`имя поля ${JSON.stringify(name)}: длина вне 1..255 байт`);
  }
  return nb;
}

// --- лист поля --------------------------------------------------------------

export function fieldLeaf(name: string, salt: Buffer, value: Buffer): Buffer {
  const nb = checkFieldName(name);
  if (salt.length !== SALT_LEN) {
    throw new FormatError(`соль должна быть ровно ${SALT_LEN} байт`);
  }
  return H(tag(TAG_FIELD_LEAF), lp(nb), lp(salt), lp(value));
}

// --- дерево RFC 6962 --------------------------------------------------------

function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Корень над УЖЕ готовыми листьями: повторного хеширования нет. */
export function mth(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) throw new FormatError("пустое дерево запрещено");
  if (leaves.length === 1) return leaves[0]!;
  const k = split(leaves.length);
  return H(tag(TAG_NODE), mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

export interface PathStep {
  side: "left" | "right";
  h: string;
}

/**
 * Путь принадлежности. Сторона указывается явно, а не выводится арифметикой
 * по индексу: это самая частая ошибка при переносе на другой язык.
 */
export function auditPath(idx: number, leaves: Buffer[]): PathStep[] {
  const n = leaves.length;
  if (idx < 0 || idx >= n) throw new FormatError("индекс листа вне диапазона");
  if (n === 1) return [];
  const k = split(n);
  if (idx < k) {
    return [...auditPath(idx, leaves.slice(0, k)),
            { side: "right", h: mth(leaves.slice(k)).toString("hex") }];
  }
  return [...auditPath(idx - k, leaves.slice(k)),
          { side: "left", h: mth(leaves.slice(0, k)).toString("hex") }];
}

export function applyPath(leaf: Buffer, path: PathStep[]): Buffer {
  let cur = leaf;
  for (const s of path) {
    const sib = Buffer.from(s.h, "hex");
    if (sib.length !== 32) throw new FormatError("сосед в пути должен быть 32 байта");
    if (s.side === "right") cur = H(tag(TAG_NODE), cur, sib);
    else if (s.side === "left") cur = H(tag(TAG_NODE), sib, cur);
    else throw new FormatError("сторона должна быть left или right");
  }
  return cur;
}

// --- запись -----------------------------------------------------------------

/** Поле для расчёта: либо соль со значением, либо готовый лист (вычеркнуто). */
export type LeafInput =
  | { name: string; salt: Buffer; value: Buffer }
  | { name: string; leaf: Buffer };

export function contentRoot(fields: LeafInput[]): Buffer {
  if (fields.length === 0) {
    throw new FormatError("запись должна содержать хотя бы одно поле");
  }
  const seen = new Set<string>();
  const items: Array<{ name: Buffer; leaf: Buffer }> = [];
  for (const f of fields) {
    const nb = checkFieldName(f.name);
    if (seen.has(f.name)) throw new FormatError(`повтор имени поля: ${f.name}`);
    seen.add(f.name);
    let leaf: Buffer;
    if ("leaf" in f) {
      if (f.leaf.length !== 32) throw new FormatError("готовый лист должен быть 32 байта");
      leaf = f.leaf;
    } else {
      leaf = fieldLeaf(f.name, f.salt, f.value);
    }
    items.push({ name: nb, leaf });
  }
  items.sort((a, b) => Buffer.compare(a.name, b.name));
  return mth(items.map((x) => x.leaf));
}

// --- цепь -------------------------------------------------------------------

export function genesis(streamId: string): Buffer {
  return H(tag(TAG_GENESIS),
           lp(Buffer.from(streamId, "utf8")),
           lp(Buffer.from(FORMAT_VERSION, "utf8")));
}

export function link(prev: Buffer, seq: number, croot: Buffer, ts: number): Buffer {
  if (seq < 1) throw new FormatError("seq начинается с 1");
  if (ts < 0) throw new FormatError("время не может быть отрицательным");
  if (prev.length !== 32 || croot.length !== 32) {
    throw new FormatError("отпечатки должны быть 32 байта");
  }
  return H(tag(TAG_LINK), prev, varint(seq), croot, varint(ts));
}

// --- отрезок и сутки --------------------------------------------------------

export function segLeaf(l: Buffer): Buffer {
  return H(tag(TAG_SEG_LEAF), l);
}

export function dayLeaf(c: Buffer): Buffer {
  return H(tag(TAG_DAY_LEAF), c);
}

export function segRoot(links: Buffer[]): Buffer {
  return mth(links.map(segLeaf));
}

export interface SegmentCheckpointInput {
  streamId: string;
  periodId: string;
  firstSeq: number;
  lastSeq: number;
  count: number;
  linkBefore: Buffer;
  linkLast: Buffer;
  root: Buffer;
  prevCheckpoint: Buffer;
}

export function segCkpt(s: SegmentCheckpointInput): Buffer {
  if (s.lastSeq - s.firstSeq + 1 !== s.count) {
    throw new FormatError("count не совпадает с диапазоном seq — пропуск в отрезке");
  }
  return H(tag(TAG_SEG_CKPT),
           lp(Buffer.from(s.streamId, "utf8")), lp(Buffer.from(s.periodId, "utf8")),
           varint(s.firstSeq), varint(s.lastSeq), varint(s.count),
           s.linkBefore, s.linkLast, s.root, s.prevCheckpoint);
}

export function dayRoot(segCkpts: Buffer[]): Buffer {
  return mth(segCkpts.map(dayLeaf));
}

export function dayCkpt(realmId: string, date: string, streamCount: number,
                        root: Buffer, prev: Buffer): Buffer {
  if (streamCount < 1) throw new FormatError("сутки без потоков отметки не образуют");
  return H(tag(TAG_DAY_CKPT),
           lp(Buffer.from(realmId, "utf8")), lp(Buffer.from(date, "utf8")),
           varint(streamCount), root, prev);
}
