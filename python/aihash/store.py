"""Раскладка на диске и кодирование записей.

Обычные файлы, без базы данных. Требование из плана: через семь лет
посторонний эксперт открывает каталог и понимает содержимое без нашей
инфраструктуры.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Dict, List, Optional

from . import core

RECORD_V = 1


# --- кодирование значения поля ---------------------------------------------


def encode_field(name: str, salt: bytes, value) -> dict:
    out = {"name": name, "salt": salt.hex()}
    if isinstance(value, str):
        out["s"] = value
    elif isinstance(value, (bytes, bytearray)):
        out["b"] = base64.b64encode(bytes(value)).decode("ascii")
    else:
        raise core.FormatError(
            "значение поля %r должно быть str или bytes, получено %s"
            % (name, type(value).__name__))
    return out


def raw_value(f: dict) -> bytes:
    if "s" in f and "b" in f:
        raise core.FormatError("поле %r: s и b одновременно" % f.get("name"))
    if "s" in f:
        return f["s"].encode("utf-8")
    if "b" in f:
        return base64.b64decode(f["b"])
    raise core.FormatError("поле %r: нет ни s, ни b" % f.get("name"))


def fields_for_root(fields: List[dict]) -> List[dict]:
    """Приводит поля из файла к виду, который принимает core.content_root."""
    out = []
    for f in fields:
        if "leaf" in f:
            if "salt" in f or "s" in f or "b" in f:
                raise core.FormatError(
                    "вычеркнутое поле %r сохранило соль или значение" % f.get("name"))
            out.append({"name": f["name"], "leaf": bytes.fromhex(f["leaf"])})
        else:
            out.append({"name": f["name"], "salt": bytes.fromhex(f["salt"]),
                        "value": raw_value(f)})
    return out


def record_line(seq: int, ts: int, fields: List[dict], croot: bytes,
                link: bytes) -> str:
    return json.dumps({"v": RECORD_V, "seq": seq, "ts": ts, "fields": fields,
                       "content_root": croot.hex(), "link": link.hex()},
                      ensure_ascii=False, separators=(",", ":"))


# --- атомарная запись файла -------------------------------------------------


def write_json(path: str, obj: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --- раскладка --------------------------------------------------------------


class Layout:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)

    @property
    def realm_file(self) -> str:
        return os.path.join(self.root, "realm.json")

    def stream_dir(self, stream_id: str) -> str:
        return os.path.join(self.root, "streams", stream_id)

    def meta_file(self, stream_id: str) -> str:
        return os.path.join(self.stream_dir(stream_id), "meta.json")

    def segments_dir(self, stream_id: str) -> str:
        return os.path.join(self.stream_dir(stream_id), "segments")

    def segment_file(self, stream_id: str, period: str) -> str:
        return os.path.join(self.segments_dir(stream_id), period + ".jsonl")

    def segment_ckpt_file(self, stream_id: str, period: str) -> str:
        return os.path.join(self.segments_dir(stream_id), period + ".seg.json")

    def day_file(self, date: str) -> str:
        return os.path.join(self.root, "days", date + ".day.json")

    def anchor_file(self, date: str, kind: str, ext: str) -> str:
        return os.path.join(self.root, "anchors", "%s.%s.%s" % (date, kind, ext))

    def anchors_dir(self) -> str:
        return os.path.join(self.root, "anchors")

    # --- перечисление ---

    def streams(self) -> List[str]:
        d = os.path.join(self.root, "streams")
        if not os.path.isdir(d):
            return []
        return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n)))

    def periods(self, stream_id: str) -> List[str]:
        d = self.segments_dir(stream_id)
        if not os.path.isdir(d):
            return []
        return sorted(n[:-6] for n in os.listdir(d) if n.endswith(".jsonl"))

    def dates(self) -> List[str]:
        d = os.path.join(self.root, "days")
        if not os.path.isdir(d):
            return []
        return sorted(n[:-9] for n in os.listdir(d) if n.endswith(".day.json"))

    def anchors_for(self, date: str) -> List[str]:
        d = self.anchors_dir()
        if not os.path.isdir(d):
            return []
        return sorted(os.path.join(d, n) for n in os.listdir(d)
                      if n.startswith(date + "."))

    # --- чтение ---

    def read_segment(self, stream_id: str, period: str) -> List[dict]:
        path = self.segment_file(stream_id, period)
        if not os.path.exists(path):
            return []
        out = []
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise core.FormatError(
                        "%s строка %d: не разбирается как JSON (%s)"
                        % (path, lineno, e))
        return out

    def read_segment_tail(self, stream_id: str, period: str) -> Optional[dict]:
        """Последняя запись отрезка без чтения всего файла.

        Пишущему нужен только кончик цепи. Читать ради него весь журнал —
        значит превращать запуск процесса в минуты на журнале за несколько лет.
        Проверка цепи целиком — работа верификатора, а не писателя.
        """
        path = self.segment_file(stream_id, period)
        if not os.path.exists(path):
            return None
        size = os.path.getsize(path)
        if size == 0:
            return None
        window = 1 << 16
        while True:
            with open(path, "rb") as f:
                f.seek(max(0, size - window))
                chunk = f.read()
            if not chunk.endswith(b"\n"):
                raise core.FormatError(
                    "%s: последняя строка оборвана — процесс упал посреди записи. "
                    "Обрежьте файл до последнего перевода строки; всё до него "
                    "проверяется как обычно." % path)
            lines = [l for l in chunk.split(b"\n") if l.strip()]
            if lines:
                try:
                    return json.loads(lines[-1].decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
            if window >= size:
                raise core.FormatError("%s: последняя запись не разбирается" % path)
            window = min(window * 8, size)

    def read_segment_ckpt(self, stream_id: str, period: str) -> Optional[dict]:
        path = self.segment_ckpt_file(stream_id, period)
        return read_json(path) if os.path.exists(path) else None

    def read_day(self, date: str) -> Optional[dict]:
        path = self.day_file(date)
        return read_json(path) if os.path.exists(path) else None

    def realm(self) -> Dict:
        return read_json(self.realm_file)


def init_realm(layout: Layout, realm_id: str, now_ms: int) -> dict:
    core.check_id(realm_id, "realm_id")
    os.makedirs(layout.root, exist_ok=True)
    os.makedirs(os.path.join(layout.root, "streams"), exist_ok=True)
    os.makedirs(os.path.join(layout.root, "days"), exist_ok=True)
    os.makedirs(layout.anchors_dir(), exist_ok=True)
    if os.path.exists(layout.realm_file):
        existing = layout.realm()
        if existing["realm_id"] != realm_id:
            raise core.FormatError(
                "каталог принадлежит установке %r, а не %r"
                % (existing["realm_id"], realm_id))
        return existing
    obj = {"format": core.FORMAT_VERSION, "hash": core.HASH_NAME,
           "realm_id": realm_id, "created": now_ms}
    write_json(layout.realm_file, obj)
    return obj


def init_stream(layout: Layout, stream_id: str, now_ms: int) -> dict:
    core.check_id(stream_id, "stream_id")
    os.makedirs(layout.segments_dir(stream_id), exist_ok=True)
    path = layout.meta_file(stream_id)
    if os.path.exists(path):
        return read_json(path)
    obj = {"format": core.FORMAT_VERSION, "stream_id": stream_id,
           "genesis": core.genesis(stream_id).hex(), "created": now_ms}
    write_json(path, obj)
    return obj
