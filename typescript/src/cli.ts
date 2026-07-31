#!/usr/bin/env node
/**
 * Командная строка для Node-установок.
 *
 *   aihash-ts seal    --root ./journal [--date ГГГГ-ММ-ДД] [--anchor feed]
 *   aihash-ts explain --root ./journal --stream S --seq N [--out ep.seal]
 *   aihash-ts verify  <файл.seal | каталог журнала>
 *   aihash-ts redact  --root ./journal --stream S --seq N --fields a,b --reason "..."
 *   aihash-ts ls      --root ./journal
 *
 * Вывод верификатора — не «OK», а фраза, которую можно вставить в письмо.
 *
 * Коды возврата проверки пакета:
 *   0 — сходится и запечатано: содержимое доказано
 *   3 — сходится, но пломба не поставлена либо не подтверждена здесь: НЕ доказано
 *   1 — не сходится
 *   2 — файл не прочитан
 *
 * Код 3 объединяет два разных случая намеренно, но словами их различать
 * обязательно: «пломбы нет» вместо «пломба не подтверждена» занижает
 * доказательство исправного журнала.
 */

import * as path from "node:path";
import { statSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { FormatError } from "./core.js";
import { Layout, periodOf, exists } from "./store.js";
import { Journal } from "./journal.js";
import { sealDay, anchorDay } from "./seal.js";
import { build } from "./bundle.js";
import { ANCHOR_FAILED, ANCHOR_UNVERIFIED } from "./seal.js";
import { verifyBundle, verifyJournal, BROKEN, SEALED, UNVERIFIED,
         type Result } from "./verify.js";

function arg(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

function need(argv: string[], name: string): string {
  const v = arg(argv, name);
  if (!v) throw new FormatError(`не указан --${name}`);
  return v;
}

function full(ms: number | null | undefined): string {
  if (!ms) return "—";
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}.${d.getUTCFullYear()} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`;
}

const ANCHOR_WORD: Record<string, string> = {
  ok: "verified", unverified: "not verified", failed: "DOES NOT MATCH",
};

function printBroken(r: Result): void {
  console.log("DOES NOT MATCH\n");
  for (const p of r.problems) console.log("  " + p);
  console.log("\nThe previous content is not stored and cannot be recovered —");
  console.log("only the fingerprint is kept. Which field was changed cannot be");
  console.log("told from the fingerprint: it covers the record as a whole.");
}

function printBundle(r: Result, file: string): void {
  if (r.status === BROKEN) return printBroken(r);
  console.log(`Bundle ${path.basename(file)}`);
  console.log(`  journal ${r.realmId}, stream ${r.streamId}, segment ${r.periodId}`);
  if (r.disclosed) {
    console.log(`  ${r.disclosed[0]} of ${r.disclosed[1]} records in the segment disclosed`);
  }
  console.log("");
  for (const c of r.checks) console.log("  matches: " + c.label);
  console.log("");
  for (const a of r.anchors) {
    console.log(`  seal ${a.type}: ${ANCHOR_WORD[a.status]} — ${a.detail}`);
  }
  console.log("");
  if (r.status === SEALED) {
    console.log("Verdict: the content matches its fingerprint, the fingerprint is");
    console.log("in the daily tree, and the daily checkpoint is sealed.");
  } else if (r.status === UNVERIFIED) {
    console.log("Verdict: the content matches its fingerprint and is in the daily tree.");
    console.log("A seal was placed for these days but is not confirmed here — see");
    console.log("its line above. Integrity is not proven until verifying the seal");
    console.log("is finished; this is not the same as having no seal.");
  } else {
    console.log("Verdict: the content matches its fingerprint and is in the daily tree,");
    console.log("but no seal was placed for these days. Integrity is not proven —");
    console.log("only internal consistency is.");
  }
  if (r.lowerMs) {
    console.log(`The record existed no earlier than ${full(r.lowerMs)} (${r.lowerSource})`);
    console.log("and no later than the seal.");
  }
}

// Чего не хватает и где это взять. Без второй половины сообщение бесполезно:
// получатель узнаёт, что проверка неполна, и не узнаёт, как её достроить.
const HOW_TO_CONFIRM: Record<string, string> = {
  rfc3161: "obtain the timestamp authority root certificate from the " +
           "authority itself (not from this bundle) and check the signature: " +
           "openssl ts -verify -digest <daily checkpoint> -in <file.tsr> " +
           "-CAfile <cacert.pem>",
  opentimestamps: "install the client and retry: " +
                  "pip install opentimestamps-client",
};

function printAnchorsOf(r: Result, dates: string[]): void {
  const want = new Set(dates);
  for (const a of r.anchors) {
    if (a.status !== ANCHOR_FAILED && a.date && want.has(a.date)) {
      console.log(`  ${a.date}: ${a.type} — ${a.detail}`);
    }
  }
}

// Пломба стоит, но подтвердить её нечем. Отдельный случай, а не разновидность
// «не запечатано»: для штампа RFC 3161 это ЕДИНСТВЕННЫЙ достижимый здесь исход
// — разбора CMS в SDK без зависимостей нет, — и объявлять из-за этого журнал
// незапечатанным значит занижать доказательство за его владельца.
function printUnconfirmed(r: Result): void {
  console.log(`Seal present but not confirmed here: ` +
              `${r.unverifiedDays.length} day(s) (${r.unverifiedDays.join(", ")})`);
  printAnchorsOf(r, r.unverifiedDays);
  console.log("  This is not \"no seal\": a seal was placed for these days, " +
              "verifying it was not finished.");
  const unverified = new Set(r.unverifiedDays);
  const seen = new Set<string>();
  for (const a of r.anchors) {
    if (!a.date || !unverified.has(a.date) || a.status !== ANCHOR_UNVERIFIED
        || !a.placed || seen.has(a.type)) continue;
    seen.add(a.type);
    const how = HOW_TO_CONFIRM[a.type];
    if (how) console.log(`  ${a.type}: ${how}`);
  }
}

function printJournal(r: Result): void {
  if (r.status === BROKEN) return printBroken(r);
  console.log(`Journal ${r.realmId}: ${r.records} record(s)`);
  if (r.redacted) console.log(`  fields redacted: ${r.redacted}`);
  console.log("The chain matches end to end.");
  if (r.sealedDays.length) {
    console.log(`Days sealed: ${r.sealedDays.length} (${r.sealedDays.join(", ")})`);
    printAnchorsOf(r, r.sealedDays);
  }
  if (r.unverifiedDays.length) printUnconfirmed(r);
  if (r.openDays.length) {
    console.log(`Days not sealed: ${r.openDays.length} ` +
                `(${r.openDays.join(", ")}) — a seal is placed once a day`);
  }
}

async function main(argv: string[]): Promise<number> {
  const cmd = argv[0];
  switch (cmd) {
    case "seal": {
      const root = need(argv, "root");
      const layout = new Layout(root);
      const realm = layout.realm();
      const today = periodOf(Date.now());
      const dates = arg(argv, "date")
        ? [arg(argv, "date")!]
        : [...new Set(layout.streams().flatMap((s) =>
            layout.periods(s).filter((p) =>
              p < today && layout.readSegmentCkpt(s, p) === null)))].sort();
      if (!dates.length) { console.log("нечего закрывать"); return 0; }
      const kinds = (arg(argv, "anchor") ?? "feed").split(",").filter(Boolean);
      let rc = 0;
      for (const date of dates) {
        const day = await sealDay(layout, realm.realm_id, date);
        if (!day) { console.log(`${date}: записей нет`); continue; }
        console.log(`${date}: закрыто, потоков ${day.streams.length}, ` +
                    `суточная отметка ${day.day_checkpoint.slice(0, 16)}…`);
        const res = await anchorDay(layout, date, kinds, arg(argv, "feed-path"));
        for (const x of res) {
          if (x.ok) console.log(`  пломба ${x.type} поставлена` +
                                (x.detail ? ` (${x.detail})` : ""));
          else console.log(`  пломба ${x.type} не поставлена: ${x.error}`);
        }
        if (!res.some((x) => x.ok)) {
          console.log("  ни одна пломба не поставлена — сутки остаются незапечатанными");
          rc = 1;
        }
      }
      return rc;
    }
    case "explain": {
      const root = need(argv, "root");
      const stream = need(argv, "stream");
      const seqs = need(argv, "seq").split(",").map(Number);
      const out = arg(argv, "out") ?? `${stream}-${seqs.join("-")}.seal`;
      const page = arg(argv, "verifier-page")
        // URL.pathname ломается на Windows: там нужен fileURLToPath.
        ?? path.join(path.dirname(fileURLToPath(import.meta.url)),
                     "..", "..", "..", "verifier", "dist", "verify.html");
      await build(root, stream, seqs, out,
                  { verifierPage: exists(page) ? page : undefined });
      console.log(`собран ${out}`);
      console.log(`проверка у получателя:  aihash-verify ${path.basename(out)}`);
      return 0;
    }
    case "verify": {
      const target = argv[1];
      if (!target) throw new FormatError("укажите файл .seal или каталог журнала");
      const isDir = statSync(target).isDirectory();
      const r = isDir ? verifyJournal(target) : await verifyBundle(target);
      if (isDir) printJournal(r); else printBundle(r, target);
      if (r.status === BROKEN) return 1;
      // Ноль на пакете без пломбы означал бы «всё в порядке» там, где не
      // доказано ничего.
      return !isDir && r.status !== SEALED ? 3 : 0;
    }
    case "redact": {
      const root = need(argv, "root");
      const layout = new Layout(root);
      const j = await Journal.open(root, layout.realm().realm_id,
                                   { beaconSource: null });
      try {
        const s = await j.stream(need(argv, "stream"));
        const seq = await s.redact(Number(need(argv, "seq")),
                                   need(argv, "fields").split(",").map((x) => x.trim()),
                                   need(argv, "reason"));
        console.log(`вычеркнуто из записи ${need(argv, "seq")}; ` +
                    `событие записано как ${seq}`);
        console.log("отпечаток записи не изменился, цепь продолжает сходиться");
      } finally {
        await j.close();
      }
      return 0;
    }
    case "ls": {
      const layout = new Layout(need(argv, "root"));
      const realm = layout.realm();
      console.log(`журнал ${realm.realm_id}, формат ${realm.format}`);
      for (const s of layout.streams()) {
        console.log(`  поток ${s}`);
        for (const p of layout.periods(s)) {
          const n = layout.readSegment(s, p).length;
          const ck = layout.readSegmentCkpt(s, p);
          console.log(`    ${p}: записей ${n}, ${ck ? "закрыт" : "открыт"}`);
        }
      }
      return 0;
    }
    default:
      console.error("использование: aihash-ts <seal|explain|verify|redact|ls> ...");
      return 2;
  }
}

main(process.argv.slice(2))
  .then((rc) => process.exit(rc))
  .catch((e) => {
    console.error(e instanceof FormatError ? `ошибка формата: ${e.message}` : e);
    process.exit(2);
  });
