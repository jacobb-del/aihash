"""Эталонная реализация формата aihash v1.

Назначение — только генерация и проверка тестовых векторов. Это не библиотека
продукта: здесь нет буферизации, приёмников, пломб и обработки ошибок. Код
написан так, чтобы его можно было прочитать целиком и сверить со спецификацией
строка в строку.
"""

import hashlib

FORMAT_VERSION = "aihash/1"
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


def varint(n):
    """LEB128 без знака. Отрицательные значения запрещены."""
    if n < 0:
        raise ValueError("varint: отрицательное значение")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def lp(b):
    """Байты с префиксом длины."""
    return varint(len(b)) + b


def H(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


# --- уровень 1: поле записи -------------------------------------------------


def field_leaf(name, salt, value):
    nb = name.encode("utf-8")
    if not 1 <= len(nb) <= 255:
        raise ValueError("длина имени поля вне 1..255 байт")
    if len(salt) != SALT_LEN:
        raise ValueError("соль должна быть ровно %d байт" % SALT_LEN)
    return H(bytes([TAG_FIELD_LEAF]), lp(nb), lp(salt), lp(value))


# --- уровень 2: дерево (RFC 6962) -------------------------------------------


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    """Корень дерева над уже готовыми листьями. Пустое дерево запрещено."""
    n = len(leaves)
    if n == 0:
        raise ValueError("пустое дерево запрещено")
    if n == 1:
        return leaves[0]
    k = _split(n)
    return H(bytes([TAG_NODE]), mth(leaves[:k]), mth(leaves[k:]))


def audit_path(idx, leaves):
    """Путь принадлежности. Сторона указана явно, чтобы реализации не считали
    её арифметикой по индексу — это самая частая ошибка при переносе."""
    n = len(leaves)
    if not 0 <= idx < n:
        raise ValueError("индекс вне диапазона")
    if n == 1:
        return []
    k = _split(n)
    if idx < k:
        return audit_path(idx, leaves[:k]) + [("right", mth(leaves[k:]))]
    return audit_path(idx - k, leaves[k:]) + [("left", mth(leaves[:k]))]


def apply_path(leaf, path):
    cur = leaf
    for side, sibling in path:
        if side == "right":
            cur = H(bytes([TAG_NODE]), cur, sibling)
        elif side == "left":
            cur = H(bytes([TAG_NODE]), sibling, cur)
        else:
            raise ValueError("сторона должна быть left или right")
    return cur


# --- уровень 3: запись ------------------------------------------------------


def content_root(fields):
    """fields — список словарей: {name, salt, value} для раскрытого поля
    или {name, leaf} для вычеркнутого."""
    if not fields:
        raise ValueError("запись должна содержать хотя бы одно поле")
    seen = set()
    items = []
    for f in fields:
        nb = f["name"].encode("utf-8")
        if nb in seen:
            raise ValueError("повтор имени поля: %s" % f["name"])
        seen.add(nb)
        if "leaf" in f:
            leaf = f["leaf"]
            if len(leaf) != 32:
                raise ValueError("готовый лист должен быть 32 байта")
        else:
            leaf = field_leaf(f["name"], f["salt"], f["value"])
        items.append((nb, leaf))
    items.sort(key=lambda t: t[0])
    return mth([leaf for _, leaf in items])


# --- уровень 4: цепь --------------------------------------------------------


def genesis(stream_id):
    return H(
        bytes([TAG_GENESIS]),
        lp(stream_id.encode("utf-8")),
        lp(FORMAT_VERSION.encode("utf-8")),
    )


def link(prev_link, seq, croot, ts_ms):
    if seq < 1:
        raise ValueError("seq начинается с 1")
    if len(prev_link) != 32 or len(croot) != 32:
        raise ValueError("отпечатки должны быть 32 байта")
    return H(bytes([TAG_LINK]), prev_link, varint(seq), croot, varint(ts_ms))


# --- уровень 5: отрезок -----------------------------------------------------


def seg_leaf(link_hash):
    return H(bytes([TAG_SEG_LEAF]), link_hash)


def seg_root(link_hashes):
    return mth([seg_leaf(l) for l in link_hashes])


def seg_ckpt(stream_id, period_id, first_seq, last_seq, count,
             link_before, link_last, root, prev_ckpt):
    if last_seq - first_seq + 1 != count:
        raise ValueError("count не совпадает с диапазоном seq")
    return H(
        bytes([TAG_SEG_CKPT]),
        lp(stream_id.encode("utf-8")),
        lp(period_id.encode("utf-8")),
        varint(first_seq),
        varint(last_seq),
        varint(count),
        link_before,
        link_last,
        root,
        prev_ckpt,
    )


# --- уровень 6: сутки -------------------------------------------------------


def day_leaf(ckpt):
    return H(bytes([TAG_DAY_LEAF]), ckpt)


def day_root(seg_ckpts_sorted_by_stream_id):
    return mth([day_leaf(c) for c in seg_ckpts_sorted_by_stream_id])


def day_ckpt(realm_id, date, stream_count, root, prev_ckpt):
    if stream_count < 1:
        raise ValueError("сутки без потоков не образуют отметку")
    return H(
        bytes([TAG_DAY_CKPT]),
        lp(realm_id.encode("utf-8")),
        lp(date.encode("utf-8")),
        varint(stream_count),
        root,
        prev_ckpt,
    )


# --- вспомогательное для векторов ------------------------------------------


def test_salt(stream_id, seq, name):
    """Соли в векторах выведены по фиксированному правилу, чтобы набор можно
    было пересобрать побайтово. В продукте соль берётся из CSPRNG."""
    seed = "aihash/v1/test-salt/%s/%d/%s" % (stream_id, seq, name)
    return hashlib.sha256(seed.encode("utf-8")).digest()[:SALT_LEN]
