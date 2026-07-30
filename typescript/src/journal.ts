/**
 * Запись в журнал: потоки, фоновая укладка на диск, откат отрезка.
 *
 * Приоритеты горячего пути те же, что в Python — иначе две реализации давали
 * бы журналы с разными гарантиями при одинаковом формате:
 *
 * 1. Никогда не терять запись молча — очередь ограничена, переполнение даёт
 *    явную ошибку, а не тихий сброс.
 * 2. Никогда не создавать ложных пробелов — seq присваивается в момент
 *    укладки на диск, а не вызова. Иначе падение процесса оставит дыру в
 *    нумерации, неотличимую от подчистки.
 * 3. Не блокировать вызывающий код.
 * 4. Синхронный режим — на явно помеченных критичных событиях.
 */

import * as fsp from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import * as path from "node:path";

import * as core from "./core.js";
import * as store from "./store.js";
import { fetchBeacon, type BeaconValue } from "./beacon.js";

export class Overflow extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Overflow";
  }
}

export class WriterFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WriterFailed";
  }
}

export type Fields = Record<string, store.FieldValue>;

export interface JournalOptions {
  queueSize?: number;
  putTimeoutMs?: number;
  syncTimeoutMs?: number;
  beaconSource?: string | null;
  beaconTimeoutMs?: number;
  clock?: () => number;
}

interface Item {
  fields: Fields | null;
  ts: number;
  sync: boolean;
  redact?: { seq: number; names: string[]; reason: string };
  resolve: (seq: number) => void;
  reject: (e: Error) => void;
}

export class Stream {
  readonly streamId: string;
  private readonly journal: Journal;
  private readonly layout: store.Layout;

  private queue: Item[] = [];
  private spaceWaiters: Array<() => void> = [];
  private idleWaiters: Array<() => void> = [];
  private running = false;
  private failure: Error | null = null;
  private closed = false;

  private period: string | null = null;
  private fh: FileHandle | null = null;
  private dirty = false;
  private seq = 0;
  private linkHash: Buffer;

  private constructor(journal: Journal, streamId: string) {
    this.journal = journal;
    this.streamId = core.checkId(streamId, "stream_id");
    this.layout = journal.layout;
    this.linkHash = core.genesis(this.streamId);
  }

  static async open(journal: Journal, streamId: string): Promise<Stream> {
    const s = new Stream(journal, streamId);
    await store.initStream(s.layout, streamId, journal.now());
    s.resume();
    return s;
  }

  /**
   * Взять кончик цепи, не перечитывая журнал.
   *
   * Раньше здесь читалась вся история: на журнале за несколько лет это минуты
   * и гигабайты памяти при каждом запуске процесса. Пишущему нужен только
   * последний seq и последнее звено — сходимость цепи проверяет верификатор.
   */
  private resume(): void {
    const periods = this.layout.periods(this.streamId);
    for (let i = periods.length - 1; i >= 0; i--) {
      const tip = this.layout.readSegmentTail(this.streamId, periods[i]!);
      if (!tip) continue;
      this.seq = tip.seq;
      this.linkHash = Buffer.from(tip.link, "hex");
      return;
    }
  }

  /**
   * Записать событие.
   *
   * Возвращает seq только при sync — в асинхронном режиме номер ещё не
   * присвоен, и выдумывать его было бы враньём.
   */
  async record(fields: Fields, opts: { ts?: number; sync?: boolean } = {}):
      Promise<number | null> {
    this.raiseIfFailed();
    if (this.closed) throw new WriterFailed("поток закрыт");
    const names = Object.keys(fields);
    if (names.length === 0) {
      throw new core.FormatError("fields должен быть непустым объектом");
    }
    for (const n of names) {
      if (n.startsWith("_")) {
        throw new core.FormatError(`имя ${n} зарезервировано форматом (префикс _)`);
      }
    }
    return this.enqueue({ fields, ts: opts.ts ?? this.journal.now(),
                          sync: opts.sync === true });
  }

  /**
   * Вычеркнуть значения полей из записи seq.
   *
   * Удаляются значение и соль, лист дерева остаётся: отпечаток записи не
   * меняется, цепь продолжает сходиться. Само вычёркивание пишется в цепь
   * отдельной записью — объяснённый и датированный пробел перестаёт быть
   * подозрительным.
   */
  async redact(seq: number, names: string[], reason: string): Promise<number> {
    this.raiseIfFailed();
    if (names.length === 0) throw new core.FormatError("не указано ни одного поля");
    const r = await this.enqueue({
      fields: null, ts: this.journal.now(), sync: true,
      redact: { seq, names: [...names], reason },
    });
    return r!;
  }

  private async enqueue(partial: Omit<Item, "resolve" | "reject">):
      Promise<number | null> {
    // Проверка места и постановка в очередь обязаны идти без await между ними,
    // иначе сотня одновременных вызовов проскакивает охрану целиком: все они
    // видят пустую очередь до того, как хоть один успел в неё попасть.
    const deadline = Date.now() + this.journal.putTimeoutMs;
    while (this.queue.length >= this.journal.queueSize) {
      if (Date.now() >= deadline) {
        throw new Overflow(
          `очередь потока ${this.streamId} переполнена ` +
          `(${this.journal.queueSize}), запись не принята — тихо сбрасывать ` +
          "событие доказательственный журнал не вправе");
      }
      await new Promise<void>((r) => {
        const t = setTimeout(r, 2);
        this.spaceWaiters.push(() => { clearTimeout(t); r(); });
      });
    }
    return new Promise<number | null>((resolve, reject) => {
      const item: Item = { ...partial, resolve: resolve as (n: number) => void, reject };
      this.queue.push(item);
      void this.pump();
      if (!partial.sync) {
        // Асинхронный режим: обещание исполняется фактом принятия в очередь.
        resolve(null);
        item.resolve = () => {};
        item.reject = (e) => { this.failure ??= e; };
      }
    });
  }

  private async pump(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      while (this.queue.length) {
        const item = this.queue.shift()!;
        this.spaceWaiters.splice(0).forEach((w) => w());
        try {
          const seq = item.redact
            ? await this.doRedact(item.redact)
            : await this.append(item.fields!, item.ts);
          if (item.sync) await this.syncToDisk();
          item.resolve(seq);
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
          if (!(err instanceof core.FormatError)) this.failure = err;
          item.reject(err);
        }
      }
      await this.syncToDisk();
    } finally {
      this.running = false;
      this.idleWaiters.splice(0).forEach((w) => w());
    }
  }

  private async append(fields: Fields, ts: number): Promise<number> {
    await this.ensurePeriod(store.periodOf(this.journal.now()));
    const stored: store.StoredField[] = [];
    const calc: core.LeafInput[] = [];
    for (const [name, value] of Object.entries(fields)) {
      const salt = core.newSalt();
      stored.push(store.encodeField(name, salt, value));
      calc.push({ name, salt,
                  value: typeof value === "string"
                    ? Buffer.from(value, "utf8") : Buffer.from(value) });
    }
    const croot = core.contentRoot(calc);
    const seq = this.seq + 1;
    const link = core.link(this.linkHash, seq, croot, ts);
    await this.fh!.write(store.recordLine({
      v: store.RECORD_V, seq, ts, fields: stored,
      content_root: croot.toString("hex"), link: link.toString("hex"),
    }) + "\n");
    this.seq = seq;
    this.linkHash = link;
    this.dirty = true;
    return seq;
  }

  private async doRedact(r: { seq: number; names: string[]; reason: string }):
      Promise<number> {
    // Сегмент читается с диска: открытый файл обязан быть закрыт до чтения.
    await this.closeFile();
    this.period = null;
    let target: { period: string; recs: store.StoredRecord[] } | null = null;
    for (const p of this.layout.periods(this.streamId)) {
      const recs = this.layout.readSegment(this.streamId, p);
      if (recs.length && recs[0]!.seq <= r.seq && r.seq <= recs[recs.length - 1]!.seq) {
        target = { period: p, recs };
        break;
      }
    }
    if (!target) throw new core.FormatError(`запись seq=${r.seq} не найдена`);

    let found = false;
    for (const rec of target.recs) {
      if (rec.seq !== r.seq) continue;
      const present = new Set(rec.fields.map((f) => f.name));
      const missing = r.names.filter((n) => !present.has(n));
      if (missing.length) {
        throw new core.FormatError(
          `в записи seq=${r.seq} нет полей: ${missing.join(", ")}`);
      }
      rec.fields = rec.fields.map((f) => {
        if (!r.names.includes(f.name) || f.leaf !== undefined) return f;
        const leaf = core.fieldLeaf(f.name, Buffer.from(f.salt!, "hex"),
                                    store.rawValue(f));
        return { name: f.name, leaf: leaf.toString("hex"),
                 redacted: { at: this.journal.now(), seq: this.seq + 1 } };
      });
      const croot = core.contentRoot(store.fieldsForRoot(rec.fields));
      if (croot.toString("hex") !== rec.content_root) {
        throw new core.FormatError(
          `вычёркивание изменило отпечаток записи seq=${r.seq} — нарушение формата`);
      }
      found = true;
    }
    if (!found) throw new core.FormatError(`запись seq=${r.seq} не найдена`);

    const file = this.layout.segmentFile(this.streamId, target.period);
    const tmp = `${file}.tmp`;
    const fh = await fsp.open(tmp, "w");
    try {
      await fh.writeFile(target.recs.map(store.recordLine).join("\n") + "\n", "utf8");
      await fh.sync();
    } finally {
      await fh.close();
    }
    await fsp.rename(tmp, file);

    await this.ensurePeriod(store.periodOf(this.journal.now()));
    return this.append({
      "_redaction.target_seq": String(r.seq),
      "_redaction.fields": r.names.join(","),
      "_redaction.reason": r.reason,
    } as Fields, this.journal.now());
  }

  private async ensurePeriod(period: string): Promise<void> {
    if (period === this.period) {
      // Пломбу ставит отдельный процесс по расписанию: отрезок мог быть
      // запечатан, пока мы держали его открытым. Дописать в него — значит
      // порвать его отметку, поэтому проверяем на каждой записи.
      this.assertNotSealed(period);
      return;
    }
    await this.closeFile();
    this.assertNotSealed(period);
    this.period = period;
    const file = this.layout.segmentFile(this.streamId, period);
    await fsp.mkdir(path.dirname(file), { recursive: true });
    const existed = store.exists(file);
    this.fh = await fsp.open(file, "a");
    if (!existed) await this.writeBeacon();
  }

  private assertNotSealed(period: string): void {
    if (store.exists(this.layout.segmentCkptFile(this.streamId, period))) {
      throw new core.FormatError(
        `отрезок ${period} потока ${this.streamId} уже запечатан — дописывать ` +
        "в него нельзя, это порвало бы его отметку");
    }
  }

  private async writeBeacon(): Promise<void> {
    const b: BeaconValue | null = await this.journal.beacon();
    if (!b) return;
    await this.append({
      "_beacon.source": b.source,
      "_beacon.round": String(b.round),
      "_beacon.value": b.value,
      "_beacon.fetched_at": String(b.fetchedAt),
    } as Fields, this.journal.now());
  }

  private async syncToDisk(): Promise<void> {
    if (!this.fh || !this.dirty) return;
    await this.fh.sync();
    this.dirty = false;
  }

  private async closeFile(): Promise<void> {
    if (!this.fh) return;
    await this.syncToDisk();
    await this.fh.close();
    this.fh = null;
  }

  private raiseIfFailed(): void {
    if (this.failure) throw new WriterFailed(`запись остановлена: ${this.failure.message}`);
  }

  /** Дождаться, пока всё принятое окажется на диске. */
  async flush(): Promise<void> {
    this.raiseIfFailed();
    while (this.running || this.queue.length) {
      await new Promise<void>((r) => this.idleWaiters.push(r));
    }
    await this.syncToDisk();
    this.raiseIfFailed();
  }

  async close(): Promise<void> {
    await this.flush();
    this.closed = true;
    await this.closeFile();
  }
}

export class Journal {
  readonly layout: store.Layout;
  readonly realmId: string;
  readonly queueSize: number;
  readonly putTimeoutMs: number;
  readonly syncTimeoutMs: number;
  private readonly beaconSource: string | null;
  private readonly beaconTimeoutMs: number;
  private readonly clock: () => number;
  private readonly streamsMap = new Map<string, Stream>();
  // Открытие потока асинхронно: без учёта уже идущих открытий два
  // одновременных вызова stream("a") создадут два писателя на один файл.
  private readonly opening = new Map<string, Promise<Stream>>();
  private readonly beaconCache = new Map<string, BeaconValue | null>();

  private constructor(root: string, realm: string, o: JournalOptions) {
    this.layout = new store.Layout(root);
    this.realmId = core.checkId(realm, "realm_id");
    this.queueSize = o.queueSize ?? 10000;
    this.putTimeoutMs = o.putTimeoutMs ?? 5000;
    this.syncTimeoutMs = o.syncTimeoutMs ?? 30000;
    this.beaconSource = o.beaconSource === undefined ? "drand" : o.beaconSource;
    this.beaconTimeoutMs = o.beaconTimeoutMs ?? 2000;
    this.clock = o.clock ?? (() => Date.now());
  }

  static async open(root: string, realm: string, o: JournalOptions = {}):
      Promise<Journal> {
    const j = new Journal(root, realm, o);
    await store.initRealm(j.layout, realm, j.now());
    return j;
  }

  /** Часы установки. Подменяются в тестах; в проде это системное время. */
  now(): number {
    return this.clock();
  }

  async stream(streamId: string): Promise<Stream> {
    const ready = this.streamsMap.get(streamId);
    if (ready) return ready;
    const inFlight = this.opening.get(streamId);
    if (inFlight) return inFlight;
    const p = Stream.open(this, streamId)
      .then((s) => {
        this.streamsMap.set(streamId, s);
        return s;
      })
      .finally(() => {
        this.opening.delete(streamId);
      });
    this.opening.set(streamId, p);
    return p;
  }

  /**
   * Маяк на текущие сутки. Недоступность внешнего сервиса не должна ронять
   * приложение клиента — просто не будет нижней границы времени.
   */
  async beacon(): Promise<BeaconValue | null> {
    if (!this.beaconSource) return null;
    const day = store.periodOf(this.now());
    if (!this.beaconCache.has(day)) {
      this.beaconCache.set(day, await fetchBeacon(this.beaconSource, this.beaconTimeoutMs));
    }
    return this.beaconCache.get(day) ?? null;
  }

  async record(streamId: string, fields: Fields,
               opts?: { ts?: number; sync?: boolean }): Promise<number | null> {
    return (await this.stream(streamId)).record(fields, opts);
  }

  async flush(): Promise<void> {
    for (const s of this.streamsMap.values()) await s.flush();
  }

  async close(): Promise<void> {
    for (const s of this.streamsMap.values()) await s.close();
    this.streamsMap.clear();
  }
}

/** Журнал с одним заранее выбранным потоком — ради обещания «одна строка». */
export class BoundStream {
  constructor(readonly journal: Journal, readonly stream: Stream) {}

  record(fields: Fields, opts?: { ts?: number; sync?: boolean }) {
    return this.stream.record(fields, opts);
  }

  redact(seq: number, names: string[], reason: string) {
    return this.stream.redact(seq, names, reason);
  }

  flush() {
    return this.stream.flush();
  }

  close() {
    return this.journal.close();
  }
}

export async function open(root: string, opts: JournalOptions &
                           { realm: string; stream: string }): Promise<BoundStream> {
  const { realm, stream, ...rest } = opts;
  const j = await Journal.open(root, realm, rest);
  return new BoundStream(j, await j.stream(stream));
}
