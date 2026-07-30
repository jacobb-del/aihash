/**
 * aihash — доказуемый журнал работы ИИ-системы.
 *
 * Подключение в одну строку:
 *
 *     import { open } from "@aihash/aihash";
 *     const log = await open("./journal", {
 *       realm: "romashka-prod", stream: "voice-eu-3" });
 *
 *     await log.record({
 *       actor: "assistant",
 *       "output.text": "возврат придёт в течение 5 дней",
 *       "config.model": "gpt-4o-2026-02-11",
 *     });
 *
 * Дальше 364 дня в году ничего не происходит. В день, когда прилетела
 * претензия, собирается пакет доказательства, который оппонент проверяет у
 * себя — офлайн, без обращения к вам.
 */

export * from "./core.js";
export { Journal, Stream, BoundStream, Overflow, WriterFailed, open } from "./journal.js";
export type { Fields, JournalOptions } from "./journal.js";
export { Layout, periodOf } from "./store.js";
export type { StoredRecord, StoredField, SegmentCheckpoint, DayCheckpoint } from "./store.js";
export { sealSegment, sealDay, anchorDay, verifyFeed, verifyAnchorBlob } from "./seal.js";
export { build as buildBundle, renderReport } from "./bundle.js";
export type { Manifest } from "./bundle.js";
export { verifyJournal, verifyBundle, SEALED, OPEN, BROKEN } from "./verify.js";
export type { Result } from "./verify.js";
export { fetchBeacon, lowerBoundMs } from "./beacon.js";
export const VERSION = "0.1.0";
