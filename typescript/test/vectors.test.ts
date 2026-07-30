/**
 * Главный тест этапа: TypeScript обязан сойтись с векторами этапа 0 побайтово.
 *
 * Это те же файлы, по которым проверяются Python, Go и браузерный
 * верификатор. Если этот тест падает, реализация несовместима со
 * спецификацией и всё остальное значения не имеет.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";

import * as c from "../src/core.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const V = join(HERE, "..", "..", "..", "spec", "vectors");

function load(name: string): any {
  return JSON.parse(readFileSync(join(V, `${name}.json`), "utf8"));
}

interface VecField {
  name: string;
  salt?: string;
  s?: string;
  b?: string;
  leaf?: string;
}

function rawValue(f: VecField): Buffer {
  assert.ok(!(f.s !== undefined && f.b !== undefined), "s и b одновременно");
  if (f.s !== undefined) return Buffer.from(f.s, "utf8");
  if (f.b !== undefined) return Buffer.from(f.b, "base64");
  throw new Error(`поле ${f.name}: нет ни s, ни b`);
}

function toLeafInputs(fields: VecField[]): c.LeafInput[] {
  return fields.map((f) =>
    f.leaf !== undefined
      ? { name: f.name, leaf: Buffer.from(f.leaf, "hex") }
      : { name: f.name, salt: Buffer.from(f.salt!, "hex"), value: rawValue(f) });
}

const hex = (b: Buffer) => b.toString("hex");

test("varint — LEB128 без знака", () => {
  for (const x of load("01-varint").cases) {
    assert.equal(hex(c.varint(x.value)), x.hex, `varint(${x.value})`);
  }
});

test("лист поля — UTF-8, пустое значение, произвольные байты", () => {
  for (const x of load("02-field-leaf").cases as VecField[] & { leaf: string }[]) {
    const got = c.fieldLeaf(x.name, Buffer.from(x.salt!, "hex"), rawValue(x));
    assert.equal(hex(got), x.leaf, `лист поля ${x.name}`);
  }
});

test("дерево RFC 6962 и пути принадлежности", () => {
  for (const x of load("03-merkle").cases) {
    const leaves = x.leaves.map((h: string) => Buffer.from(h, "hex"));
    assert.equal(hex(c.mth(leaves)), x.root, `корень n=${x.n}`);
    for (const ap of x.audit_paths) {
      assert.equal(hex(c.applyPath(leaves[ap.index], ap.path)), x.root,
                   `путь n=${x.n} i=${ap.index}`);
      assert.deepEqual(c.auditPath(ap.index, leaves), ap.path,
                       `построенный путь n=${x.n} i=${ap.index}`);
    }
  }
});

test("отпечатки содержимого записей", () => {
  for (const r of load("04-record").records) {
    assert.equal(hex(c.contentRoot(toLeafInputs(r.fields))), r.content_root,
                 `запись seq=${r.seq}`);
  }
});

test("нулевое звено и цепь", () => {
  for (const s of load("05-chain").streams) {
    assert.equal(hex(c.genesis(s.stream_id)), s.genesis, `нулевое звено ${s.stream_id}`);
    let prev: Buffer = Buffer.from(s.genesis, "hex");
    for (const l of s.links) {
      prev = c.link(prev, l.seq, Buffer.from(l.content_root, "hex"), l.ts);
      assert.equal(hex(prev), l.link, `звено ${s.stream_id} seq=${l.seq}`);
    }
  }
});

test("вычёркивание не меняет отпечаток записи", () => {
  const d = load("06-redaction");
  const after = c.contentRoot(toLeafInputs(d.fields_after));
  assert.equal(hex(after), d.content_root_after);
  assert.equal(d.content_root_after, d.content_root_before,
               "вычёркивание изменило отпечаток — это нарушение формата");
  for (const f of d.fields_after as VecField[]) {
    if (f.leaf !== undefined) {
      assert.ok(f.salt === undefined && f.s === undefined && f.b === undefined,
                `вычеркнутое поле ${f.name} сохранило соль или значение`);
    }
  }
});

test("отметки отрезков", () => {
  const links = new Map<string, Map<number, Buffer>>();
  for (const s of load("05-chain").streams) {
    const m = new Map<number, Buffer>();
    for (const l of s.links) m.set(l.seq, Buffer.from(l.link, "hex"));
    links.set(s.stream_id, m);
  }
  for (const x of load("07-segment").cases) {
    const ls: Buffer[] = [];
    for (let q = x.first_seq; q <= x.last_seq; q++) {
      ls.push(links.get(x.stream_id)!.get(q)!);
    }
    const root = c.segRoot(ls);
    assert.equal(hex(root), x.segment_root, `корень отрезка ${x.stream_id} ${x.period_id}`);
    const ck = c.segCkpt({
      streamId: x.stream_id, periodId: x.period_id, firstSeq: x.first_seq,
      lastSeq: x.last_seq, count: x.count,
      linkBefore: Buffer.from(x.link_before, "hex"),
      linkLast: Buffer.from(x.link_last, "hex"), root,
      prevCheckpoint: Buffer.from(x.prev_checkpoint, "hex"),
    });
    assert.equal(hex(ck), x.checkpoint, `отметка отрезка ${x.stream_id} ${x.period_id}`);
  }
});

test("суточная отметка — то, что уходит под пломбу", () => {
  const d = load("08-day");
  assert.deepEqual(d.streams, [...d.streams].sort(), "потоки не отсортированы");
  const ckpts = d.segment_checkpoints.map((h: string) => Buffer.from(h, "hex"));
  const root = c.dayRoot(ckpts);
  assert.equal(hex(root), d.day_root);
  const ck = c.dayCkpt(d.realm_id, d.date, ckpts.length, root,
                       Buffer.from(d.prev_checkpoint, "hex"));
  assert.equal(hex(ck), d.day_checkpoint);
  assert.equal(d.anchored_target, d.day_checkpoint);
});

test("сквозной путь: от поля записи до отпечатка под пломбой", () => {
  const inc = load("09-inclusion");
  const rec = load("04-record").records.find((r: any) => r.seq === inc.seq);
  assert.equal(hex(c.contentRoot(toLeafInputs(rec.fields))), inc.content_root);
  const leaf = c.segLeaf(Buffer.from(inc.link, "hex"));
  assert.equal(hex(leaf), inc.segment_leaf);
  assert.equal(hex(c.applyPath(leaf, inc.segment_path)), inc.segment_root);
  const dl = c.dayLeaf(Buffer.from(inc.segment_checkpoint, "hex"));
  assert.equal(hex(dl), inc.day_leaf);
  assert.equal(hex(c.applyPath(dl, inc.day_path)), inc.day_root);
});

test("отрицательные случаи обязаны отвергаться", () => {
  const cases: Array<[string, () => unknown]> = [
    ["запись без полей", () => c.contentRoot([])],
    ["повтор имени поля", () => c.contentRoot([
      { name: "a", salt: Buffer.alloc(16), value: Buffer.from("1") },
      { name: "a", salt: Buffer.alloc(16, 1), value: Buffer.from("2") }])],
    ["пустое дерево", () => c.mth([])],
    ["соль не 16 байт", () => c.fieldLeaf("a", Buffer.alloc(8), Buffer.from("v"))],
    ["пустое имя поля", () => c.fieldLeaf("", Buffer.alloc(16), Buffer.from("v"))],
    ["seq меньше 1", () => c.link(c.ZERO32, 0, c.ZERO32, 0)],
    ["отрицательное время", () => c.link(c.ZERO32, 1, c.ZERO32, -1)],
    ["отрицательный varint", () => c.varint(-1)],
    ["дробный varint", () => c.varint(1.5)],
    ["сторона не left/right", () =>
      c.applyPath(c.ZERO32, [{ side: "middle" as any, h: c.ZERO32.toString("hex") }])],
    ["count не совпадает с диапазоном", () => c.segCkpt({
      streamId: "s", periodId: "2026-03-12", firstSeq: 1, lastSeq: 5, count: 4,
      linkBefore: c.ZERO32, linkLast: c.ZERO32, root: c.ZERO32,
      prevCheckpoint: c.ZERO32 })],
    ["готовый лист не 32 байта", () =>
      c.contentRoot([{ name: "a", leaf: Buffer.alloc(8) }])],
  ];
  for (const [label, fn] of cases) {
    assert.throws(fn, c.FormatError, `должно было быть отвергнуто: ${label}`);
  }
});
