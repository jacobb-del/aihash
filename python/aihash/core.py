"""Примитивы формата aihash v1.

Нормативный источник — FORMAT.md. При расхождении прав документ.
Модуль обязан сходиться с spec/vectors побайтово; это проверяется тестом
tests/test_vectors.py, который читает те же файлы, что и spec/tools/check.py.

Здесь нет ввода-вывода, потоков и сети. Только чистые функции.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, List, Sequence, Tuple

FORMAT_VERSION = "aihash/1"
HASH_NAME = "sha256"
SALT_LEN = 16
ZERO32 = bytes(32)

TAG_FIELD_LEAF = 0x01
TAG_NODE = 0x02
TAG_LINK = 0x03
TAG_GENESIS = 0x04
TAG_SEG_LEAF = 0x05
TAG_SEG_CKPT = 0x06
TAG_DAY_LEAF = 0x07
TAG_DAY_CKPT = 0x08

_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")


class FormatError(ValueError):
    """Нарушение спецификации формата."""


def varint(n: int) -> bytes:
    if n < 0:
        raise FormatError("varint: отрицательное значение")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def lp(b: bytes) -> bytes:
    return varint(len(b)) + b


def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def check_id(value: str, what: str) -> str:
    """Идентификатор потока становится именем каталога, поэтому проверка здесь
    не косметическая. Точка и две точки состоят из разрешённых символов, но
    выводят запись за пределы отведённого ей каталога, а имя с ведущей точкой
    прячет журнал от обычного просмотра."""
    b = value.encode("utf-8")
    if not 1 <= len(b) <= 64:
        raise FormatError("%s: длина вне 1..64 байт" % what)
    if not set(value) <= _ID_CHARS:
        raise FormatError("%s: допустимы только A-Z a-z 0-9 . _ : -" % what)
    if value.startswith("."):
        raise FormatError(
            "%s: имя не может начинаться с точки (%r) — оно становится именем "
            "каталога" % (what, value))
    return value


def check_field_name(name: str) -> bytes:
    nb = name.encode("utf-8")
    if not 1 <= len(nb) <= 255:
        raise FormatError("имя поля %r: длина вне 1..255 байт" % name)
    return nb


# --- лист поля --------------------------------------------------------------


def field_leaf(name: str, salt: bytes, value: bytes) -> bytes:
    nb = check_field_name(name)
    if len(salt) != SALT_LEN:
        raise FormatError("соль должна быть ровно %d байт" % SALT_LEN)
    return H(bytes([TAG_FIELD_LEAF]), lp(nb), lp(salt), lp(value))


# --- дерево RFC 6962 --------------------------------------------------------


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: Sequence[bytes]) -> bytes:
    """Корень над уже готовыми листьями. Повторного хеширования листьев нет."""
    n = len(leaves)
    if n == 0:
        raise FormatError("пустое дерево запрещено")
    if n == 1:
        return leaves[0]
    k = _split(n)
    return H(bytes([TAG_NODE]), mth(leaves[:k]), mth(leaves[k:]))


def audit_path(idx: int, leaves: Sequence[bytes]) -> List[Tuple[str, bytes]]:
    n = len(leaves)
    if not 0 <= idx < n:
        raise FormatError("индекс листа вне диапазона")
    if n == 1:
        return []
    k = _split(n)
    if idx < k:
        return audit_path(idx, leaves[:k]) + [("right", mth(leaves[k:]))]
    return audit_path(idx - k, leaves[k:]) + [("left", mth(leaves[:k]))]


def apply_path(leaf: bytes, path: Iterable[Tuple[str, bytes]]) -> bytes:
    cur = leaf
    for side, sibling in path:
        if len(sibling) != 32:
            raise FormatError("сосед в пути должен быть 32 байта")
        if side == "right":
            cur = H(bytes([TAG_NODE]), cur, sibling)
        elif side == "left":
            cur = H(bytes([TAG_NODE]), sibling, cur)
        else:
            raise FormatError("сторона должна быть left или right")
    return cur


# --- запись -----------------------------------------------------------------


def content_root(fields: Sequence[dict]) -> bytes:
    """fields: {"name","salt","value"} для раскрытого поля,
    {"name","leaf"} для вычеркнутого."""
    if not fields:
        raise FormatError("запись должна содержать хотя бы одно поле")
    seen = set()
    items = []
    for f in fields:
        nb = check_field_name(f["name"])
        if nb in seen:
            raise FormatError("повтор имени поля: %s" % f["name"])
        seen.add(nb)
        if "leaf" in f:
            leaf = f["leaf"]
            if len(leaf) != 32:
                raise FormatError("готовый лист должен быть 32 байта")
        else:
            leaf = field_leaf(f["name"], f["salt"], f["value"])
        items.append((nb, leaf))
    items.sort(key=lambda t: t[0])
    return mth([leaf for _, leaf in items])


# --- цепь -------------------------------------------------------------------


def genesis(stream_id: str) -> bytes:
    return H(bytes([TAG_GENESIS]),
             lp(stream_id.encode("utf-8")),
             lp(FORMAT_VERSION.encode("utf-8")))


def link(prev_link: bytes, seq: int, croot: bytes, ts_ms: int) -> bytes:
    if seq < 1:
        raise FormatError("seq начинается с 1")
    if ts_ms < 0:
        raise FormatError("время не может быть отрицательным")
    if len(prev_link) != 32 or len(croot) != 32:
        raise FormatError("отпечатки должны быть 32 байта")
    return H(bytes([TAG_LINK]), prev_link, varint(seq), croot, varint(ts_ms))


# --- отрезок ----------------------------------------------------------------


def seg_leaf(link_hash: bytes) -> bytes:
    return H(bytes([TAG_SEG_LEAF]), link_hash)


def seg_root(link_hashes: Sequence[bytes]) -> bytes:
    return mth([seg_leaf(l) for l in link_hashes])


def seg_ckpt(stream_id: str, period_id: str, first_seq: int, last_seq: int,
             count: int, link_before: bytes, link_last: bytes, root: bytes,
             prev_ckpt: bytes) -> bytes:
    if last_seq - first_seq + 1 != count:
        raise FormatError("count не совпадает с диапазоном seq — пропуск в отрезке")
    return H(bytes([TAG_SEG_CKPT]),
             lp(stream_id.encode("utf-8")), lp(period_id.encode("utf-8")),
             varint(first_seq), varint(last_seq), varint(count),
             link_before, link_last, root, prev_ckpt)


# --- сутки ------------------------------------------------------------------


def day_leaf(ckpt: bytes) -> bytes:
    return H(bytes([TAG_DAY_LEAF]), ckpt)


def day_root(seg_ckpts_sorted_by_stream: Sequence[bytes]) -> bytes:
    return mth([day_leaf(c) for c in seg_ckpts_sorted_by_stream])


def day_ckpt(realm_id: str, date: str, stream_count: int, root: bytes,
             prev_ckpt: bytes) -> bytes:
    if stream_count < 1:
        raise FormatError("сутки без потоков отметки не образуют")
    return H(bytes([TAG_DAY_CKPT]),
             lp(realm_id.encode("utf-8")), lp(date.encode("utf-8")),
             varint(stream_count), root, prev_ckpt)
