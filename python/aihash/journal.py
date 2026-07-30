"""Запись в журнал: потоки, фоновая запись на диск, откат отрезка.

Приоритеты горячего пути, в порядке из плана:

1. Никогда не терять запись молча — очередь ограничена, переполнение даёт
   явную ошибку, а не тихий сброс.
2. Никогда не создавать ложных пробелов — seq присваивается в момент
   долговечной записи, а не вызова. Иначе падение процесса оставляет дыру в
   нумерации, неотличимую от подчистки.
3. Не блокировать вызывающий код.
4. Синхронный режим — на явно помеченных критичных событиях.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from typing import Dict, List, Optional

from . import beacon as beacon_mod
from . import core, store

log = logging.getLogger("aihash")


class Overflow(RuntimeError):
    """Очередь записи переполнена. Запись НЕ принята."""


class WriterFailed(RuntimeError):
    """Фоновая запись остановлена ошибкой. Журнал больше не принимает записи."""


def now_ms() -> int:
    return int(time.time() * 1000)


def period_of(ms: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ms / 1000))


class _Item:
    __slots__ = ("fields", "ts", "done", "seq", "error", "redact")

    def __init__(self, fields, ts, done, redact=None):
        self.fields = fields
        self.ts = ts
        self.done = done
        self.seq = None
        self.error = None
        self.redact = redact


class Stream:
    def __init__(self, journal: "Journal", stream_id: str):
        self.journal = journal
        self.stream_id = core.check_id(stream_id, "stream_id")
        self._layout = journal.layout
        store.init_stream(self._layout, stream_id, journal.now())

        self._q: queue.Queue = queue.Queue(journal.queue_size)
        self._error: Optional[BaseException] = None
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._idle.set()

        self._period: Optional[str] = None
        self._fh = None
        self._dirty = False
        self._seq = 0
        self._link = core.genesis(stream_id)
        self._resume()

        self._thread = threading.Thread(
            target=self._run, name="aihash-writer:%s" % stream_id, daemon=True)
        self._thread.start()

    # --- восстановление состояния из файлов ---

    def _resume(self) -> None:
        """Взять кончик цепи, не перечитывая журнал.

        Раньше здесь читалась вся история: на журнале за несколько лет это
        минуты и гигабайты памяти при каждом запуске процесса. Пишущему нужен
        только последний seq и последнее звено — сходимость цепи проверяет
        верификатор.
        """
        for p in reversed(self._layout.periods(self.stream_id)):
            tip = self._layout.read_segment_tail(self.stream_id, p)
            if tip is None:
                continue
            self._seq = int(tip["seq"])
            self._link = bytes.fromhex(tip["link"])
            return

    # --- публичный интерфейс ---

    def record(self, fields: Dict, ts: Optional[int] = None,
               sync: bool = False) -> Optional[int]:
        """Записать событие.

        Возвращает seq в синхронном режиме и None в асинхронном: в асинхронном
        номер ещё не присвоен, и выдумывать его было бы враньём.
        """
        self._raise_if_failed()
        if not isinstance(fields, dict) or not fields:
            raise core.FormatError("fields должен быть непустым словарём")
        for name in fields:
            if name.startswith("_"):
                raise core.FormatError(
                    "имя %r зарезервировано форматом (префикс _)" % name)
        item = _Item(dict(fields), ts if ts is not None else self.journal.now(),
                     threading.Event() if sync else None)
        self._enqueue(item)
        if not sync:
            return None
        if not item.done.wait(self.journal.sync_timeout):
            raise WriterFailed("синхронная запись не подтверждена за %.1f с"
                               % self.journal.sync_timeout)
        if item.error:
            raise item.error
        return item.seq

    def _enqueue(self, item: _Item) -> None:
        self._idle.clear()
        try:
            self._q.put(item, timeout=self.journal.put_timeout)
        except queue.Full:
            # _idle трогать нельзя: очередь как раз полна, и объявить её
            # разобранной значит заставить flush() вернуться раньше времени.
            raise Overflow(
                "очередь потока %s переполнена (%d), запись не принята — "
                "тихо сбрасывать событие доказательственный журнал не вправе"
                % (self.stream_id, self.journal.queue_size))

    def flush(self, timeout: float = 30.0) -> None:
        """Дождаться, пока всё принятое окажется на диске."""
        self._raise_if_failed()
        if not self._idle.wait(timeout):
            raise WriterFailed("очередь не разобрана за %.1f с" % timeout)
        self._raise_if_failed()

    def close(self) -> None:
        self._stop.set()
        self._q.put(None)
        self._thread.join(timeout=60.0)
        self._raise_if_failed()

    def _raise_if_failed(self) -> None:
        if self._error is not None:
            raise WriterFailed("запись остановлена: %s" % self._error) from self._error

    # --- фоновый поток ---

    def _run(self) -> None:
        try:
            while True:
                try:
                    item = self._q.get(timeout=self.journal.flush_interval)
                except queue.Empty:
                    self._sync_to_disk()
                    if self._q.empty():
                        self._idle.set()
                    continue
                if item is None:
                    break
                if not self._handle(item):
                    break
                if self._q.empty():
                    self._sync_to_disk()
                    self._idle.set()
        except BaseException as e:  # noqa: BLE001 — поток не должен умереть молча
            self._error = e
            log.error("aihash: поток записи %s остановлен: %s", self.stream_id, e,
                      exc_info=True)
        finally:
            try:
                self._drain()
            except BaseException as e:  # noqa: BLE001
                if self._error is None:
                    self._error = e
            self._close_file()
            self._idle.set()

    def _handle(self, item: _Item) -> bool:
        """Обработать одно событие. False — поток записи дальше не живёт.

        Некорректный вызов (запечатанный отрезок, негодное поле) отклоняет
        именно этот вызов и не роняет поток: синхронный вызывающий обязан
        узнать причину сразу, а не через таймаут. Отказ ввода-вывода
        останавливает поток целиком — писать дальше некуда.
        """
        try:
            self._write(item)
        except core.FormatError as e:
            if item.done is not None:
                item.error = e
                item.done.set()
                return True
            # В асинхронном режиме сообщить некому: помечаем поток сломанным,
            # чтобы отказ всплыл на следующем вызове, а не пропал молча.
            self._error = e
            log.error("aihash: поток записи %s остановлен некорректным вызовом: %s",
                      self.stream_id, e)
            return False
        except BaseException as e:  # noqa: BLE001
            self._error = e
            log.error("aihash: поток записи %s остановлен: %s", self.stream_id, e,
                      exc_info=True)
            if item.done is not None:
                item.error = WriterFailed(str(e))
                item.done.set()
            return False
        if item.done is not None:
            self._sync_to_disk()
            item.done.set()
        return True

    def _drain(self) -> None:
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                continue
            if self._error is None:
                self._handle(item)
            elif item.done is not None:
                item.error = WriterFailed(str(self._error))
                item.done.set()
        self._sync_to_disk()

    def redact(self, seq: int, field_names: List[str], reason: str,
               timeout: float = 30.0) -> int:
        """Вычеркнуть значения полей из записи seq.

        Удаляются значение и соль, лист дерева остаётся — отпечаток записи не
        меняется, цепь продолжает сходиться. Само вычёркивание записывается в
        цепь отдельной записью: пробел, который объяснён и датирован,
        перестаёт быть подозрительным.

        Выполняется в потоке записи, чтобы не разъехаться с открытым файлом.
        """
        self._raise_if_failed()
        if not field_names:
            raise core.FormatError("не указано ни одного поля")
        item = _Item(None, self.journal.now(), threading.Event(),
                     redact=(seq, list(field_names), reason))
        self._enqueue(item)
        if not item.done.wait(timeout):
            raise WriterFailed("вычёркивание не подтверждено за %.1f с" % timeout)
        if item.error:
            raise item.error
        return item.seq

    def _write(self, item: _Item) -> None:
        if item.redact is not None:
            self._do_redact(*item.redact)
            item.seq = self._seq
            return
        self._ensure_period(period_of(self.journal.now()))
        self._append(item.fields, item.ts)
        item.seq = self._seq

    def _do_redact(self, seq: int, field_names: List[str], reason: str) -> None:
        # Сегмент читается с диска, поэтому буфер открытого файла обязан быть
        # сброшен ДО чтения. Иначе всё, что ещё не долетело до диска, не попадёт
        # в прочитанное — и будет затёрто при перезаписи файла.
        self._close_file()
        self._period = None
        target_period = None
        for p in self._layout.periods(self.stream_id):
            recs = self._layout.read_segment(self.stream_id, p)
            if recs and recs[0]["seq"] <= seq <= recs[-1]["seq"]:
                target_period, target_recs = p, recs
                break
        if target_period is None:
            raise core.FormatError("запись seq=%d не найдена" % seq)

        found = False
        for rec in target_recs:
            if rec["seq"] != seq:
                continue
            names = {f["name"] for f in rec["fields"]}
            missing = [n for n in field_names if n not in names]
            if missing:
                raise core.FormatError(
                    "в записи seq=%d нет полей: %s" % (seq, ", ".join(missing)))
            new_fields = []
            for f in rec["fields"]:
                if f["name"] not in field_names or "leaf" in f:
                    new_fields.append(f)
                    continue
                leaf = core.field_leaf(f["name"], bytes.fromhex(f["salt"]),
                                       store.raw_value(f))
                new_fields.append({"name": f["name"], "leaf": leaf.hex(),
                                   "redacted": {"at": self.journal.now(),
                                                "seq": self._seq + 1}})
            rec["fields"] = new_fields
            croot = core.content_root(store.fields_for_root(new_fields))
            if croot.hex() != rec["content_root"]:
                raise core.FormatError(
                    "вычёркивание изменило отпечаток записи seq=%d — "
                    "это нарушение формата" % seq)
            found = True
        if not found:
            raise core.FormatError("запись seq=%d не найдена" % seq)

        path = self._layout.segment_file(self.stream_id, target_period)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for rec in target_recs:
                f.write(store.record_line(rec["seq"], rec["ts"], rec["fields"],
                                          bytes.fromhex(rec["content_root"]),
                                          bytes.fromhex(rec["link"])) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

        self._ensure_period(period_of(self.journal.now()))
        self._append({"_redaction.target_seq": str(seq),
                      "_redaction.fields": ",".join(field_names),
                      "_redaction.reason": reason}, self.journal.now())

    def _append(self, fields: Dict, ts: int) -> None:
        enc, calc = [], []
        for name, value in fields.items():
            salt = core.new_salt()
            enc.append(store.encode_field(name, salt, value))
            calc.append({"name": name, "salt": salt,
                         "value": value.encode("utf-8")
                         if isinstance(value, str) else bytes(value)})
        croot = core.content_root(calc)
        seq = self._seq + 1
        link = core.link(self._link, seq, croot, ts)
        self._fh.write(store.record_line(seq, ts, enc, croot, link) + "\n")
        self._seq, self._link, self._dirty = seq, link, True

    def _assert_not_sealed(self, period: str) -> None:
        if self._layout.read_segment_ckpt(self.stream_id, period) is not None:
            raise core.FormatError(
                "отрезок %s потока %s уже запечатан — дописывать в него нельзя, "
                "это порвало бы его отметку" % (period, self.stream_id))

    def _ensure_period(self, period: str) -> None:
        if period == self._period:
            # Пломбу ставит отдельный процесс по расписанию: отрезок мог быть
            # запечатан, пока мы держали его открытым. Дописать в него — значит
            # порвать его отметку, поэтому проверяем на каждой записи.
            self._assert_not_sealed(period)
            return
        self._close_file()
        self._assert_not_sealed(period)
        self._period = period
        path = self._layout.segment_file(self.stream_id, period)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        existed = os.path.exists(path)
        self._fh = open(path, "a", encoding="utf-8")
        if not existed:
            self._write_beacon()

    def _write_beacon(self) -> None:
        b = self.journal.beacon()
        if b is None:
            return
        self._append({"_beacon.source": b["source"],
                      "_beacon.round": str(b["round"]),
                      "_beacon.value": b["value"],
                      "_beacon.fetched_at": str(b["fetched_at"])}, self.journal.now())

    def _sync_to_disk(self) -> None:
        if self._fh is None or not self._dirty:
            return
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._dirty = False

    def _close_file(self) -> None:
        if self._fh is None:
            return
        self._sync_to_disk()
        self._fh.close()
        self._fh = None


class Journal:
    """Установка: каталог, набор потоков, общая политика записи."""

    def __init__(self, root: str, realm: str, *, queue_size: int = 10000,
                 put_timeout: float = 5.0, flush_interval: float = 1.0,
                 sync_timeout: float = 30.0, beacon_source: Optional[str] = "drand",
                 beacon_timeout: float = 2.0, clock=None):
        self.layout = store.Layout(root)
        self.realm_id = core.check_id(realm, "realm_id")
        self.queue_size = queue_size
        self.put_timeout = put_timeout
        self.flush_interval = flush_interval
        self.sync_timeout = sync_timeout
        self.beacon_source = beacon_source
        self.beacon_timeout = beacon_timeout
        self._clock = clock or now_ms
        self._streams: Dict[str, Stream] = {}
        self._lock = threading.Lock()
        self._beacon_cache: Dict[str, Optional[dict]] = {}
        store.init_realm(self.layout, realm, self.now())

    def now(self) -> int:
        """Часы установки. Подменяются в тестах; в проде это системное время."""
        return self._clock()

    def stream(self, stream_id: str) -> Stream:
        with self._lock:
            s = self._streams.get(stream_id)
            if s is None:
                s = Stream(self, stream_id)
                self._streams[stream_id] = s
            return s

    def beacon(self) -> Optional[dict]:
        """Маяк на текущие сутки. Недоступность внешнего сервиса не должна
        ронять приложение клиента — просто не будет нижней границы времени."""
        if not self.beacon_source:
            return None
        day = period_of(self.now())
        if day not in self._beacon_cache:
            self._beacon_cache[day] = beacon_mod.fetch(
                self.beacon_source, timeout=self.beacon_timeout)
        return self._beacon_cache[day]

    def record(self, stream_id: str, fields: Dict, **kw):
        return self.stream(stream_id).record(fields, **kw)

    def redact(self, stream_id: str, seq: int, fields: List[str], reason: str) -> int:
        return self.stream(stream_id).redact(seq, fields, reason)

    def flush(self, timeout: float = 30.0) -> None:
        for s in list(self._streams.values()):
            s.flush(timeout)

    def close(self) -> None:
        """Закрыть все потоки. Отказ одного не оставляет остальные открытыми:
        незакрытый поток — это несброшенный буфер, то есть потерянные записи."""
        errors = []
        for s in list(self._streams.values()):
            try:
                s.close()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)
        self._streams.clear()
        if errors:
            raise errors[0]

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class BoundStream:
    """То, что возвращает aihash.open() — журнал с одним заранее выбранным
    потоком. Ради обещания «одна строка кода»."""

    def __init__(self, journal: Journal, stream_id: str):
        self.journal = journal
        self.stream = journal.stream(stream_id)

    def record(self, fields: Dict, **kw):
        return self.stream.record(fields, **kw)

    def redact(self, seq: int, fields: List[str], reason: str) -> int:
        return self.stream.redact(seq, fields, reason)

    def flush(self, timeout: float = 30.0) -> None:
        self.stream.flush(timeout)

    def close(self) -> None:
        self.journal.close()

    def __enter__(self) -> "BoundStream":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
