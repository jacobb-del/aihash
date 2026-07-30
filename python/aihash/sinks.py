"""Приёмники сохранности.

Вход на рынок — «ваши записи исчезают через 30 дней». Значит продукт обязан
реально решать хранение, а не только подлинность. Приёмник копирует
запечатанные сутки туда, где их нельзя стереть.

Что здесь честно, а что нет:

  local  — снимает право на запись с файлов. Защищает от случайности и от
           скрипта, который «прибрался». От того, кто владеет каталогом, не
           защищает никак, и приёмник говорит это сам.
  s3     — Object Lock в режиме COMPLIANCE: до истечения срока объект не может
           удалить даже владелец учётной записи. Принуждение обеспечивает AWS,
           а не мы. Наша ответственность — запросить правильный режим и срок и
           отказаться писать в корзину без включённого Object Lock, чтобы
           клиент не считал себя защищённым, не будучи защищённым.

Архив по раскладке — обычный журнал aihash, поэтому его проверяет тот же
верификатор без единой правки.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import stat
from typing import List, Optional

from . import core, store


class SinkError(RuntimeError):
    """Приёмник не принял артефакт. Считать сутки сохранёнными нельзя."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Sink:
    name = "sink"

    def put(self, rel: str, data: bytes,
            retain_until: Optional[dt.datetime]) -> dict:
        raise NotImplementedError

    def get(self, rel: str) -> Optional[bytes]:
        raise NotImplementedError

    def describe(self) -> dict:
        raise NotImplementedError


# --- локальный архив --------------------------------------------------------


class LocalArchiveSink(Sink):
    """Каталог, в котором с файлов снято право на запись.

    Раскладка совпадает с журналом, поэтому архив проверяется командой
    `aihash verify <каталог>` и бинарём `aihash-verify` без изменений.
    """

    name = "local"

    def __init__(self, root: str, immutable: bool = False):
        self.root = os.path.abspath(root)
        self.immutable = immutable
        os.makedirs(self.root, exist_ok=True)

    def _path(self, rel: str) -> str:
        return os.path.join(self.root, rel.replace("/", os.sep))

    def _unlock(self, path: str) -> None:
        if not os.path.exists(path):
            return
        if self.immutable and hasattr(os, "chflags"):
            try:
                os.chflags(path, 0)
            except OSError:
                pass
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def put(self, rel: str, data: bytes,
            retain_until: Optional[dt.datetime]) -> dict:
        path = self._path(rel)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._unlock(path)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        except OSError as e:
            # Отказ файловой системы обязан выглядеть как отказ приёмника:
            # иначе archive_date пропустит его мимо своего перечня проблем.
            raise SinkError("не записано %s: %s" % (rel, e)) from e
        locked = False
        if self.immutable and hasattr(os, "chflags"):
            try:
                os.chflags(path, getattr(stat, "UF_IMMUTABLE", 0x00000002))
                locked = True
            except OSError:
                locked = False
        return {"sink": self.name, "key": rel, "sha256": sha256_hex(data),
                "bytes": len(data), "immutable": locked,
                "retain_until": retain_until.isoformat() if retain_until else None}

    def get(self, rel: str) -> Optional[bytes]:
        path = self._path(rel)
        if not os.path.exists(path):
            return None
        with open(path, "rb") as f:
            return f.read()

    def unlock_all(self) -> None:
        """Снять флаги, чтобы каталог можно было удалить. Нужно тестам и
        миграциям; в рабочем сценарии вызывать незачем."""
        for dirpath, _, names in os.walk(self.root):
            for n in names:
                self._unlock(os.path.join(dirpath, n))

    def describe(self) -> dict:
        return {
            "sink": self.name, "root": self.root, "immutable": self.immutable,
            "enforced_by": "файловая система",
            "honest_note":
                "право на запись снято: защищает от случайности и от скрипта, "
                "но не от того, кто владеет каталогом. Настоящую защиту даёт "
                "хранилище с блокировкой на запись.",
        }


# --- S3 Object Lock ---------------------------------------------------------


class S3ObjectLockSink(Sink):
    """Корзина S3 с включённым Object Lock, режим COMPLIANCE.

    В этом режиме объект нельзя удалить или укоротить срок хранения до его
    истечения — ни владельцу корзины, ни владельцу учётной записи, ни root.
    Это единственная часть схемы, которую не контролирует ни клиент, ни мы, и
    именно поэтому она стоит в предложении по сохранности первой.
    """

    name = "s3"

    def __init__(self, bucket: str, prefix: str = "", client=None,
                 mode: str = "COMPLIANCE", require_lock: bool = True):
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise SinkError("режим блокировки должен быть COMPLIANCE или GOVERNANCE")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.mode = mode
        if client is None:
            try:
                import boto3
            except ImportError as e:
                raise SinkError(
                    "нужен boto3: pip install 'aihash[s3]'") from e
            client = boto3.client("s3")
        self.client = client
        self.lock_enabled = self._check_lock()
        if require_lock and not self.lock_enabled:
            raise SinkError(
                "в корзине %s не включён Object Lock — записи можно будет "
                "удалить, и считать их сохранёнными нельзя. Включается только "
                "при создании корзины." % bucket)

    def _check_lock(self) -> bool:
        try:
            r = self.client.get_object_lock_configuration(Bucket=self.bucket)
        except Exception:
            return False
        cfg = r.get("ObjectLockConfiguration") or {}
        return cfg.get("ObjectLockEnabled") == "Enabled"

    def _key(self, rel: str) -> str:
        return "%s/%s" % (self.prefix, rel) if self.prefix else rel

    def put(self, rel: str, data: bytes,
            retain_until: Optional[dt.datetime]) -> dict:
        kw = dict(Bucket=self.bucket, Key=self._key(rel), Body=data,
                  ChecksumAlgorithm="SHA256")
        if retain_until is not None and self.lock_enabled:
            kw["ObjectLockMode"] = self.mode
            kw["ObjectLockRetainUntilDate"] = retain_until
        try:
            r = self.client.put_object(**kw)
        except Exception as e:
            raise SinkError("S3 не принял %s: %s" % (rel, e)) from e
        return {"sink": self.name, "key": self._key(rel),
                "sha256": sha256_hex(data), "bytes": len(data),
                "version_id": r.get("VersionId"),
                "lock_mode": kw.get("ObjectLockMode"),
                "retain_until": retain_until.isoformat() if retain_until else None}

    def get(self, rel: str) -> Optional[bytes]:
        try:
            r = self.client.get_object(Bucket=self.bucket, Key=self._key(rel))
        except Exception:
            return None
        return r["Body"].read()

    def describe(self) -> dict:
        return {
            "sink": self.name, "bucket": self.bucket, "prefix": self.prefix,
            "mode": self.mode, "lock_enabled": self.lock_enabled,
            "enforced_by": "AWS S3 Object Lock",
            "honest_note":
                "срок хранения принуждает AWS, а не эта библиотека. Наша часть "
                "— запросить режим %s с верной датой и отказаться писать в "
                "корзину без Object Lock." % self.mode,
        }


# --- что именно уходит в архив ---------------------------------------------


def artifacts_for_date(layout: store.Layout, date: str) -> List[str]:
    """Пути относительно корня журнала. Архив обязан остаться пригодным для
    проверки, поэтому в него идут не только сегменты, но и всё, без чего
    верификатор не соберёт цепь."""
    rels = ["realm.json"]
    for stream_id in layout.streams():
        if date not in layout.periods(stream_id):
            continue
        rels.append("streams/%s/meta.json" % stream_id)
        rels.append("streams/%s/segments/%s.jsonl" % (stream_id, date))
        ck = layout.segment_ckpt_file(stream_id, date)
        if os.path.exists(ck):
            rels.append("streams/%s/segments/%s.seg.json" % (stream_id, date))
    if os.path.exists(layout.day_file(date)):
        rels.append("days/%s.day.json" % date)
    for path in layout.anchors_for(date):
        rels.append("anchors/" + os.path.basename(path))
    feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
    if os.path.exists(feed):
        rels.append("anchors/feed.jsonl")
    return [r for r in rels if os.path.exists(os.path.join(layout.root, r))]


def archive_date(layout: store.Layout, sinks: List[Sink], date: str,
                 retain_until: Optional[dt.datetime]) -> dict:
    """Скопировать запечатанные сутки во все приёмники.

    Незапечатанные сутки в архив не идут: блокировать на запись можно только
    то, что уже окончательно.
    """
    if layout.read_day(date) is None:
        raise SinkError(
            "сутки %s не закрыты — в архив идут только запечатанные" % date)
    if not sinks:
        raise SinkError("не задан ни один приёмник")

    rels = artifacts_for_date(layout, date)
    written, problems = [], []
    for rel in rels:
        with open(os.path.join(layout.root, rel), "rb") as f:
            data = f.read()
        for sink in sinks:
            try:
                written.append(sink.put(rel, data, retain_until))
            except SinkError as e:
                problems.append(str(e))
    return {"date": date, "artifacts": len(rels), "written": written,
            "problems": problems,
            "retain_until": retain_until.isoformat() if retain_until else None}


def verify_copies(layout: store.Layout, sinks: List[Sink], date: str) -> dict:
    """Прочитать архив обратно и сверить байты с исходником.

    «Записал» и «лежит на месте» — разные утверждения, и второе стоит
    проверять отдельно.
    """
    rels = artifacts_for_date(layout, date)
    out = {"date": date, "checked": 0, "missing": [], "differs": []}
    for rel in rels:
        with open(os.path.join(layout.root, rel), "rb") as f:
            want = sha256_hex(f.read())
        for sink in sinks:
            got = sink.get(rel)
            if got is None:
                out["missing"].append("%s: %s" % (sink.name, rel))
            elif sha256_hex(got) != want:
                out["differs"].append("%s: %s" % (sink.name, rel))
            out["checked"] += 1
    out["ok"] = not out["missing"] and not out["differs"]
    return out


def from_spec(spec: str) -> Sink:
    """Приёмник из строки: local:/путь, s3://корзина/префикс."""
    if spec.startswith("s3://"):
        rest = spec[5:]
        bucket, _, prefix = rest.partition("/")
        if not bucket:
            raise SinkError("не указана корзина: %s" % spec)
        return S3ObjectLockSink(bucket, prefix)
    if spec.startswith("local:"):
        return LocalArchiveSink(spec[6:])
    if os.sep in spec or spec.startswith("."):
        return LocalArchiveSink(spec)
    raise core.FormatError(
        "непонятный приёмник %r; ожидается local:/путь или s3://корзина/префикс"
        % spec)
