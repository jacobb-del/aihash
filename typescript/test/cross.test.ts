/**
 * Успех этапа 4 определён заранее: побайтовое совпадение с Python.
 *
 * Векторы доказывают, что совпадают отпечатки. Здесь проверяется большее:
 * журнал, написанный TypeScript, принимают Python и бинарь на Go, а журнал,
 * написанный Python, принимает TypeScript. Формат один — значит и журналы
 * взаимозаменяемы, а не только числа в тестах.
 *
 * Каждая чужая реализация пропускается отдельно, если её нет на машине.
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as fsp from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import * as store from "../src/store.js";
import { open } from "../src/journal.js";
import { sealDay, anchorDay } from "../src/seal.js";
import { build } from "../src/bundle.js";
import { verifyJournal, verifyBundle, SEALED, BROKEN } from "../src/verify.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, "..", "..", "..");
const GO = path.join(REPO, "verifier", "dist", "aihash-verify");
const PY = path.join(REPO, "python", ".venv", "bin", "python");
const JS = path.join(REPO, "verifier", "dist", "aihash-verify.js");

const REALM = "romashka-prod";
const STREAM = "voice-eu-3";

const hasGo = fs.existsSync(GO);
const hasPy = fs.existsSync(PY);
const hasJs = fs.existsSync(JS);

function run(cmd: string, args: string[], cwd?: string): { rc: number; out: string } {
  try {
    const out = execFileSync(cmd, args, { encoding: "utf8", cwd,
                                          env: { ...process.env, PYTHONPATH: path.join(REPO, "python") } });
    return { rc: 0, out };
  } catch (e) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { rc: err.status ?? 1, out: (err.stdout ?? "") + (err.stderr ?? "") };
  }
}

async function tsJournal(): Promise<{ root: string; date: string }> {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "aihash-cross-"));
  const fixed = Date.now() - 86_400_000;
  const log = await open(root, { realm: REALM, stream: STREAM,
                                 beaconSource: null, clock: () => fixed });
  await log.record({ actor: "customer", "customer.name": "Пётр Ильич Сергеев",
                     "input.text": "Когда придёт возврат?" }, { sync: true });
  await log.record({ actor: "assistant", "tool.name": "orders.get",
                     "tool.result": '{"status":"cancelled"}' }, { sync: true });
  await log.record({ actor: "assistant",
                     "output.text": "возврат придёт в течение 5 дней",
                     "config.model": "gpt-4o-2026-02-11" }, { sync: true });
  await log.record({ actor: "system", "billing.op": "RF-88214" }, { sync: true });
  await log.close();

  const layout = new store.Layout(root);
  const date = store.periodOf(fixed);
  await sealDay(layout, REALM, date);
  await anchorDay(layout, date, ["feed"]);
  return { root, date };
}

// --- журнал из TypeScript принимают остальные -------------------------------

test("TypeScript пишет — TypeScript принимает", async () => {
  const { root } = await tsJournal();
  const r = verifyJournal(root);
  assert.ok(r.problems.length === 0, r.problems.join("; "));
  assert.equal(r.status, SEALED);
  assert.equal(r.records, 4);
});

test("TypeScript пишет — бинарь на Go принимает журнал", { skip: !hasGo }, async () => {
  const { root } = await tsJournal();
  const { rc, out } = run(GO, [root]);
  assert.equal(rc, 0, out);
  assert.match(out, /Цепь сходится на всём протяжении/);
  assert.match(out, /Запечатано суток: 1/);
});

test("TypeScript пишет — Python принимает журнал", { skip: !hasPy }, async () => {
  const { root } = await tsJournal();
  const { rc, out } = run(PY, ["-m", "aihash.cli", "verify", root]);
  assert.equal(rc, 0, out);
  assert.match(out, /Цепь сходится на всём протяжении/);
});

test("пакет из TypeScript принимают Go, Python и браузерное ядро", async () => {
  const { root } = await tsJournal();
  const out = path.join(root, "ep.seal");
  await build(root, STREAM, [3], out);

  const own = await verifyBundle(out);
  assert.equal(own.status, SEALED, own.problems.join("; "));

  if (hasGo) {
    const r = run(GO, [out]);
    assert.equal(r.rc, 0, r.out);
    assert.match(r.out, /суточная отметка запечатана/);
  }
  if (hasPy) {
    const r = run(PY, ["-m", "aihash.cli", "verify", out]);
    assert.equal(r.rc, 0, r.out);
  }
  if (hasJs) {
    const r = run("node", [JS, out]);
    assert.equal(r.rc, 0, r.out);
  }
});

test("подделку в пакете из TypeScript ловят все", async () => {
  const { root } = await tsJournal();
  const good = path.join(root, "ep.seal");
  await build(root, STREAM, [3], good);

  const { readZip, writeZip } = await import("../src/zip.js");
  const files = readZip(await fsp.readFile(good));
  const edited = path.join(root, "edited.seal");
  await fsp.writeFile(edited, writeZip([...files.entries()].map(([name, data]) => ({
    name,
    data: name === "records.jsonl"
      ? Buffer.from(data.toString("utf8").replace("5 дней", "5 раб."), "utf8")
      : data,
  }))));

  assert.equal((await verifyBundle(edited)).status, BROKEN);
  if (hasGo) {
    const r = run(GO, [edited]);
    assert.equal(r.rc, 1, r.out);
    assert.match(r.out, /seq=3/);
  }
  if (hasPy) assert.equal(run(PY, ["-m", "aihash.cli", "verify", edited]).rc, 1);
  if (hasJs) assert.equal(run("node", [JS, edited]).rc, 1);
});

// --- журнал из Python принимает TypeScript ----------------------------------

test("Python пишет — TypeScript принимает журнал и пакет", { skip: !hasPy }, async () => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "aihash-py-"));
  const script = `
import aihash, json
from aihash import journal, seal, store
fixed = journal.now_ms() - 86400_000
log = aihash.BoundStream(journal.Journal(${JSON.stringify(root)}, "${REALM}",
                                         beacon_source=None, clock=lambda: fixed),
                         "${STREAM}")
for f in [{"actor": "customer", "input.text": "Когда придёт возврат?"},
          {"actor": "assistant", "output.text": "возврат придёт в течение 5 дней"}]:
    log.record(f, sync=True)
log.close()
layout = store.Layout(${JSON.stringify(root)})
date = journal.period_of(fixed)
seal.seal_day(layout, "${REALM}", date)
seal.anchor_day(layout, date, ["feed"])
from aihash import bundle
bundle.build(${JSON.stringify(root)}, "${STREAM}", [2],
             ${JSON.stringify(path.join(root, "py.seal"))})
print(date)
`;
  const r = run(PY, ["-c", script]);
  assert.equal(r.rc, 0, r.out);

  const v = verifyJournal(root);
  assert.ok(v.problems.length === 0, v.problems.join("; "));
  assert.equal(v.status, SEALED, "TypeScript не принял журнал, написанный Python");
  assert.equal(v.records, 2);

  const b = await verifyBundle(path.join(root, "py.seal"));
  assert.equal(b.status, SEALED, b.problems.join("; "));
});

test("отпечатки одной и той же записи совпадают в Python и TypeScript",
     { skip: !hasPy }, async () => {
  const { root } = await tsJournal();
  const layout = new store.Layout(root);
  const rec = layout.readSegment(STREAM, store.periodOf(Date.now() - 86_400_000))[2]!;

  const script = `
import json, sys
from aihash import core, store
rec = json.loads(sys.argv[1])
croot = core.content_root(store.fields_for_root(rec["fields"]))
print(croot.hex())
`;
  const r = run(PY, ["-c", script, JSON.stringify(rec)]);
  assert.equal(r.rc, 0, r.out);
  assert.equal(r.out.trim(), rec.content_root,
               "Python пересчитал отпечаток записи иначе, чем её записал TypeScript");
});
