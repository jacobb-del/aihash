"""Корни служб штампов, вшитые в верификатор.

Почему они здесь, а не в пакете доказательства: **корень доверия не может
ехать вместе с уликой**. Подделыватель, приложивший к пакету свой корень и
свой штамп, заверил бы сам себя. Поэтому сертификат из пакета — и точно так же
корень, вложенный в сам штамп, — не создаёт доверия никогда. Он годится ровно
на одно: назвать получателю, какой корень нужен.

Ровно так устроены браузеры: корни едут с браузером, а не с сайтом.

Честная оговорка, которую продукт обязан произносить сам: набор — умолчание
для удобства, а не заверение службы нами. Мы не удостоверяющий центр. Поэтому
вердикт называет версию набора и отпечаток сработавшего корня: оспорить сам
набор — законный ход стороны спора, и у неё должно быть, что оспаривать.

Ручное переопределение `--tsa-ca` есть всегда и главнее набора: службу, которой
в наборе нет, обязано быть можно проверить, не дожидаясь нашего выпуска.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from typing import List, Optional

ASSET = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "assets", "trust.json")

FORMAT = "aihash-trust/1"

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


class TrustError(Exception):
    """Набор не читается или не сходится с отпечатками."""


def pem_certs(data: bytes) -> List[bytes]:
    """DER каждого сертификата из PEM. Пустой список — не ошибка."""
    out = []
    for body in _PEM_RE.findall(data):
        try:
            out.append(base64.b64decode(b"".join(body.split())))
        except (binascii.Error, ValueError):
            raise TrustError("a certificate in the PEM does not parse")
    return out


def fingerprint(der: bytes) -> str:
    """SHA-256 по DER — то же число, что печатает openssl x509 -fingerprint."""
    return hashlib.sha256(der).hexdigest()


class Root:
    def __init__(self, entry: dict):
        self.id = entry["id"]
        self.name = entry["name"]
        self.sha256 = entry["sha256"]
        self.subject = entry.get("subject", "")
        self.source = entry.get("source", "")
        self.not_after = entry.get("not_after", "")
        self.pem = entry["pem"].encode("ascii")


class Store:
    def __init__(self, version: int, roots: List[Root], origin: str):
        self.version = version
        self.roots = roots
        self.origin = origin

    def __len__(self) -> int:
        return len(self.roots)

    def describe(self) -> str:
        return "%s version %d, %d root(s)" % (self.origin, self.version, len(self))


def load(path: Optional[str] = None) -> Store:
    """Прочитать вшитый набор, пересчитав отпечаток каждого корня.

    Пересчёт при загрузке — не паранойя: файл лежит на диске получателя рядом с
    установленным пакетом, и подмена там ничем не отличается от подмены в
    исходниках, кроме того, что её никто не увидит в обзоре кода.
    """
    path = path or ASSET
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise TrustError("the root store cannot be read: %s" % e)
    except json.JSONDecodeError as e:
        raise TrustError("the root store does not parse: %s" % e)

    if data.get("format") != FORMAT:
        raise TrustError("root store format %r is not supported" % data.get("format"))
    version = data.get("version")
    if not isinstance(version, int) or version < 1:
        raise TrustError("the root store has no version number")

    roots = []
    for entry in data.get("roots", []):
        try:
            root = Root(entry)
        except (KeyError, TypeError, UnicodeEncodeError) as e:
            raise TrustError("root store entry is incomplete: %s" % e)
        ders = pem_certs(root.pem)
        if len(ders) != 1:
            raise TrustError("root %s: %d certificates, expected one"
                             % (root.id, len(ders)))
        got = fingerprint(ders[0])
        if got != root.sha256:
            raise TrustError("root %s: fingerprint %s does not match the "
                             "declared %s — the store was tampered with"
                             % (root.id, got, root.sha256))
        roots.append(root)

    if not roots:
        raise TrustError("the root store is empty")
    return Store(version, roots, "root store")


def store_for(config: Optional[dict] = None) -> Optional[Store]:
    """Набор, которым проверять. None — набора нет и проверить нечем.

    `trust_store` в конфигурации существует для тестов: подделку надо уметь
    прогнать против набора, в котором нужного корня нет.
    """
    config = config or {}
    try:
        return load(config.get("trust_store"))
    except TrustError:
        return None
