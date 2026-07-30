/**
 * Настоящий ответ службы штампов времени.
 *
 * Фикстура получена живым прогоном против freetsa.org. Она закрывает ошибку,
 * из-за которой верификатор мог ложно обвинить исправный штамп: отпечаток
 * лежит в DER как есть, и проверять надо сырые байты, а не текстовый дамп.
 */

import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAnchorBlob, ANCHOR_FAILED, ANCHOR_UNVERIFIED } from "../src/seal.js";

const FIX = join(dirname(fileURLToPath(import.meta.url)),
                 "..", "..", "..", "spec", "fixtures", "rfc3161");
const has = existsSync(join(FIX, "meta.json"));
const meta = has
  ? JSON.parse(readFileSync(join(FIX, "meta.json"), "utf8")) as Record<string, string>
  : null;

test("настоящий штамп относится к своей отметке", { skip: !has }, () => {
  const data = readFileSync(join(FIX, meta!.file!));
  const target = Buffer.from(meta!.target!, "hex");
  const r = verifyAnchorBlob(meta!.file!, data, target);
  assert.notEqual(r.status, ANCHOR_FAILED,
                  `исправный штамп объявлен несходящимся: ${r.detail}`);
  assert.equal(r.type, "rfc3161");
});

test("чужая отметка отвергается", { skip: !has }, () => {
  const data = readFileSync(join(FIX, meta!.file!));
  const r = verifyAnchorBlob(meta!.file!, data, Buffer.alloc(32));
  assert.equal(r.status, ANCHOR_FAILED);
});

test("подпись без сертификата не выдаётся за проверенную", { skip: !has }, () => {
  const data = readFileSync(join(FIX, meta!.file!));
  const r = verifyAnchorBlob(meta!.file!, data, Buffer.from(meta!.target!, "hex"));
  assert.equal(r.status, ANCHOR_UNVERIFIED,
               "непроверяемая офлайн пломба не вправе называться проверенной");
});
