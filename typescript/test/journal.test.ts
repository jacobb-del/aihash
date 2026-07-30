/**
 * Сквозные проверки записи: цепь, вычёркивание, пломба, пакет, подделка.
 *
 * Гарантии горячего пути обязаны совпадать с Python — иначе две реализации
 * дают журналы с разными свойствами при одинаковом формате.
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import * as core from "../src/core.js";
import * as store from "../src/store.js";
import { Journal, Overflow, open, type Fields } from "../src/journal.js";
import { sealDay, anchorDay } from "../src/seal.js";
import { build } from "../src/bundle.js";
import { verifyJournal, verifyBundle, SEALED, OPEN, BROKEN } from "../src/verify.js";
import { readZip } from "../src/zip.js";

const REALM = "romashka-prod";
const STREAM = "voice-eu-3";

const EPISODE: Fields[] = [
  { actor: "customer", "customer.name": "Пётр Ильич Сергеев",
    "customer.phone": "+7 916 555-01-72",
    "input.text": "Когда придёт возврат за отменённый заказ?" },
  { actor: "assistant", "tool.name": "orders.get",
    "tool.result": '{"order":"A-40912","status":"cancelled"}' },
  { actor: "assistant", "output.text": "возврат придёт в течение 5 дней",
    "config.model": "gpt-4o-2026-02-11", "config.human_review": "" },
  { actor: "system", "billing.op": "RF-88214" },
];

async function tmp(): Promise<string> {
  return fsp.mkdtemp(path.join(os.tmpdir(), "aihash-ts-"));
}

function yesterday(): string {
  return store.periodOf(Date.now() - 86_400_000);
}

async function writeEpisode(root: string, past = false) {
  const fixed = Date.now() - 86_400_000;
  const log = await open(root, {
    realm: REALM, stream: STREAM, beaconSource: null,
    ...(past ? { clock: () => fixed } : {}),
  });
  const seqs: Array<number | null> = [];
  for (const f of EPISODE) seqs.push(await log.record(f, { sync: true }));
  await log.close();
  return seqs;
}

async function sealed(root: string) {
  await writeEpisode(root, true);
  const layout = new store.Layout(root);
  await sealDay(layout, REALM, yesterday());
  await anchorDay(layout, yesterday(), ["feed"]);
  return layout;
}

test("запись, цепь и проверка", async () => {
  const root = await tmp();
  assert.deepEqual(await writeEpisode(root), [1, 2, 3, 4]);
  const r = verifyJournal(root);
  assert.ok(r.problems.length === 0, r.problems.join("; "));
  assert.equal(r.records, 4);
  assert.equal(r.status, OPEN, "без пломбы состояние не может быть sealed");
});

test("асинхронная запись не возвращает номер", async () => {
  const root = await tmp();
  const log = await open(root, { realm: REALM, stream: STREAM, beaconSource: null });
  assert.equal(await log.record({ actor: "system", x: "1" }), null,
               "в асинхронном режиме номер ещё не присвоен");
  await log.flush();
  await log.close();
  assert.equal(verifyJournal(root).records, 1);
});

test("перезапуск продолжает цепь", async () => {
  const root = await tmp();
  await writeEpisode(root);
  const log = await open(root, { realm: REALM, stream: STREAM, beaconSource: null });
  assert.equal(await log.record({ actor: "system", note: "после перезапуска" },
                                { sync: true }), 5);
  await log.close();
  assert.ok(verifyJournal(root).problems.length === 0);
});

test("зарезервированный префикс отвергается", async () => {
  const root = await tmp();
  const log = await open(root, { realm: REALM, stream: STREAM, beaconSource: null });
  await assert.rejects(() => log.record({ "_beacon.round": "1" }), core.FormatError);
  await log.close();
});

test("переполнение очереди — громкая ошибка, а не тихий сброс", async () => {
  const root = await tmp();
  const j = await Journal.open(root, REALM,
                               { queueSize: 2, putTimeoutMs: 0, beaconSource: null });
  const s = await j.stream(STREAM);
  let overflow: unknown = null;
  const flying: Array<Promise<unknown>> = [];
  for (let i = 0; i < 200; i++) {
    flying.push(s.record({ actor: "system", x: String(i) }).catch((e) => {
      overflow ??= e;
    }));
  }
  await Promise.all(flying);
  assert.ok(overflow instanceof Overflow,
            "переполнение обязано быть видимым: событие не принято");
  await j.close();
});

test("вычёркивание сохраняет пломбу", async () => {
  const root = await tmp();
  const layout = await sealed(root);
  assert.equal(verifyJournal(root).status, SEALED);

  const before = layout.readSegment(STREAM, yesterday())
    .find((r) => r.seq === 1)!.content_root;

  const log = await open(root, { realm: REALM, stream: STREAM, beaconSource: null });
  const ev = await log.redact(1, ["customer.name", "customer.phone"],
                              "запрос на удаление персональных данных");
  await log.close();

  const after = layout.readSegment(STREAM, yesterday()).find((r) => r.seq === 1)!;
  assert.equal(after.content_root, before, "отпечаток записи изменился");
  for (const n of ["customer.name", "customer.phone"]) {
    const f = after.fields.find((x) => x.name === n)!;
    assert.ok(f.leaf !== undefined);
    assert.ok(f.salt === undefined && f.s === undefined);
  }
  assert.ok(!JSON.stringify(after).includes("Сергеев"),
            "персональные данные остались на диске");

  const evRec = layout.readSegment(STREAM, store.periodOf(Date.now()))
    .find((r) => r.seq === ev)!;
  const m = new Map(evRec.fields.map((f) => [f.name, f.s]));
  assert.equal(m.get("_redaction.target_seq"), "1");

  const r = verifyJournal(root);
  assert.ok(r.problems.length === 0, r.problems.join("; "));
  assert.equal(r.status, SEALED, "вычёркивание сорвало пломбу");
  assert.equal(r.redacted, 2);
});

test("в запечатанный отрезок дописать нельзя", async () => {
  const root = await tmp();
  const layout = new store.Layout(root);
  const fixed = Date.now() - 86_400_000;
  const j = await Journal.open(root, REALM, { beaconSource: null, clock: () => fixed });
  const s = await j.stream(STREAM);
  await s.record({ actor: "system", x: "1" }, { sync: true });
  await s.flush();
  await sealDay(layout, REALM, yesterday());
  await assert.rejects(() => s.record({ actor: "system", x: "2" }, { sync: true }),
                       /уже запечатан/);
  await j.close();
});

test("пакет доказательства собирается и проверяется", async () => {
  const root = await tmp();
  await sealed(root);
  const out = path.join(root, "ep.seal");
  await build(root, STREAM, [3], out);

  const names = new Set(readZip(await fsp.readFile(out)).keys());
  for (const req of ["manifest.json", "records.jsonl", "proofs.json",
                     "segment.json", "day.json", "report.html", "VERIFY.txt"]) {
    assert.ok(names.has(req), `в пакете нет ${req}`);
  }
  const r = await verifyBundle(out);
  assert.equal(r.status, SEALED, r.problems.join("; "));
  assert.deepEqual(r.disclosed, [1, 4]);
});

test("пакет не выдаёт остальной журнал", async () => {
  const root = await tmp();
  await sealed(root);
  const out = path.join(root, "ep.seal");
  await build(root, STREAM, [3], out);
  const files = readZip(await fsp.readFile(out));
  const blob = files.get("records.jsonl")!.toString("utf8") +
               files.get("report.html")!.toString("utf8");
  assert.ok(blob.includes("возврат придёт"));
  assert.ok(!blob.includes("Сергеев"), "чужая запись просочилась в пакет");
  assert.ok(!blob.includes("RF-88214"));
});

test("выписка говорит, чего она не доказывает", async () => {
  const root = await tmp();
  await sealed(root);
  const out = path.join(root, "ep.seal");
  await build(root, STREAM, [3], out);
  const html = readZip(await fsp.readFile(out)).get("report.html")!.toString("utf8");
  assert.ok(html.includes("не подтверждает"));
  assert.ok(html.includes("до поля"), "нет оговорки про локализацию расхождения");
});

test("правка одного слова ловится", async () => {
  const root = await tmp();
  const layout = await sealed(root);
  const file = layout.segmentFile(STREAM, yesterday());
  fs.writeFileSync(file, fs.readFileSync(file, "utf8")
    .replace("в течение 5 дней", "в течение 5 рабочих дней"));
  const r = verifyJournal(root);
  assert.ok(r.problems.length > 0);
  assert.ok(r.problems[0]!.includes("seq=3"), r.problems[0]);
});

test("удалённая запись ловится как пропуск", async () => {
  const root = await tmp();
  const layout = await sealed(root);
  const file = layout.segmentFile(STREAM, yesterday());
  const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l.trim());
  fs.writeFileSync(file, [lines[0], ...lines.slice(2)].join("\n") + "\n");
  const r = verifyJournal(root);
  assert.ok(r.problems.some((p) => p.includes("пропуск")), r.problems.join("; "));
});

test("подделка внутри пакета ловится", async () => {
  const root = await tmp();
  await sealed(root);
  const out = path.join(root, "ep.seal");
  await build(root, STREAM, [3], out);
  const files = readZip(await fsp.readFile(out));
  const patched = Buffer.from(files.get("records.jsonl")!.toString("utf8")
    .replace("5 дней", "5 раб."), "utf8");
  const { writeZip } = await import("../src/zip.js");
  const edited = path.join(root, "edited.seal");
  await fsp.writeFile(edited, writeZip([...files.entries()].map(([name, data]) =>
    ({ name, data: name === "records.jsonl" ? patched : data }))));

  const r = await verifyBundle(edited);
  assert.equal(r.status, BROKEN);
  assert.ok(r.problems.some((p) => p.includes("seq=3")), r.problems.join("; "));
});

test("порванная лента ловится", async () => {
  const root = await tmp();
  const layout = await sealed(root);
  const feed = path.join(layout.anchorsDir(), "feed.jsonl");
  const e = JSON.parse(fs.readFileSync(feed, "utf8").trim());
  e.target = "00".repeat(32);
  fs.writeFileSync(feed, JSON.stringify(e) + "\n");
  assert.ok(verifyJournal(root).problems.length > 0);
});

test("незапечатанные сутки — «не запечатано», а не «подделано»", async () => {
  // Сутки, пломба на которые не встала (лежала сеть), — это отсутствие
  // пломбы, а не подделка. Обвинение за чужой отказ — худший отказ
  // верификатора.
  const root = await tmp();
  const layout = new store.Layout(root);
  for (const back of [2, 1]) {
    const fixed = Date.now() - back * 86_400_000;
    const j = await Journal.open(root, REALM, { beaconSource: null, clock: () => fixed });
    const s = await j.stream(STREAM);
    await s.record({ actor: "system", x: "1" }, { sync: true });
    await j.close();
  }
  const days = layout.periods(STREAM);
  for (const d of days) await sealDay(layout, REALM, d);
  await anchorDay(layout, days[1]!, ["feed"]);

  const r = verifyJournal(root);
  assert.ok(r.problems.length === 0, r.problems.join("; "));
  assert.ok(r.openDays.includes(days[0]!), "незапечатанные сутки объявлены подделкой");
  assert.ok(r.sealedDays.includes(days[1]!));
});

test("открытие длинного журнала не перечитывает его целиком", async () => {
  const root = await tmp();
  for (const back of [3, 2, 1]) {
    const fixed = Date.now() - back * 86_400_000;
    const j = await Journal.open(root, REALM, { beaconSource: null, clock: () => fixed });
    const s = await j.stream(STREAM);
    for (let i = 0; i < 20; i++) await s.record({ actor: "system", i: String(i) });
    await j.close();
  }
  const reads: string[] = [];
  const original = store.Layout.prototype.readSegment;
  store.Layout.prototype.readSegment = function (id: string, p: string) {
    reads.push(p);
    return original.call(this, id, p);
  };
  try {
    const j = await Journal.open(root, REALM, { beaconSource: null });
    const s = await j.stream(STREAM);
    assert.equal(await s.record({ actor: "system", z: "1" }, { sync: true }), 61);
    await j.close();
  } finally {
    store.Layout.prototype.readSegment = original;
  }
  assert.deepEqual(reads, [], `при открытии прочитаны отрезки: ${reads.join(", ")}`);
});

test("оборванная последняя строка отвергается громко", async () => {
  const root = await tmp();
  const j = await Journal.open(root, REALM, { beaconSource: null });
  const s = await j.stream(STREAM);
  await s.record({ actor: "system", x: "1" }, { sync: true });
  await s.record({ actor: "system", x: "2" }, { sync: true });
  await j.close();

  const file = new store.Layout(root).segmentFile(STREAM, store.periodOf(Date.now()));
  const data = fs.readFileSync(file);
  fs.writeFileSync(file, data.subarray(0, data.length - 20));
  await assert.rejects(
    () => Journal.open(root, REALM, { beaconSource: null }).then((x) => x.stream(STREAM)),
    /оборвана/);
});
