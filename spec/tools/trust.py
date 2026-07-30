"""Набор корневых сертификатов служб штампов: чтение и проверка происхождения.

Источник истины — spec/trust/. Отсюда набор копируется в реализации; сборка
обязана падать при расхождении отпечатка, иначе корень подменяется тихой
правкой файла, а корень — это ровно то, чему верит получатель.

Отпечаток считается по DER (SHA-256), как его печатает `openssl x509
-fingerprint -sha256`. Разбор PEM здесь свой и нарочно примитивный: ни одной
зависимости, потому что этим модулем пользуется и spec, и SDK.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from typing import List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.join(HERE, "..", "trust")

FORMAT = "aihash-trust/1"

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


class TrustError(Exception):
    """Набор не читается или не сходится с манифестом."""


def pem_certs(data: bytes) -> List[bytes]:
    """Достать DER каждого сертификата из PEM. Пустой список — не ошибка."""
    out = []
    for body in _PEM_RE.findall(data):
        try:
            out.append(base64.b64decode(b"".join(body.split())))
        except (binascii.Error, ValueError):
            raise TrustError("сертификат в PEM не разбирается")
    return out


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class Root:
    def __init__(self, entry: dict, pem: bytes):
        self.id = entry["id"]
        self.name = entry["name"]
        self.sha256 = entry["sha256"]
        self.subject = entry.get("subject", "")
        self.source = entry.get("source", "")
        self.not_after = entry.get("not_after", "")
        self.pem = pem

    def __repr__(self) -> str:
        return "<Root %s %s…>" % (self.id, self.sha256[:16])


class Store:
    """Набор корней. `origin` говорит, откуда он взялся, — это попадает в
    вердикт: получатель должен знать, чем именно ему предлагают доверять."""

    def __init__(self, version: int, roots: List[Root], origin: str):
        self.version = version
        self.roots = roots
        self.origin = origin

    def __len__(self) -> int:
        return len(self.roots)

    def by_fingerprint(self, fp: str) -> Optional[Root]:
        for r in self.roots:
            if r.sha256 == fp:
                return r
        return None


def load(directory: Optional[str] = None, origin: str = "набор") -> Store:
    """Прочитать набор и сверить каждый PEM с манифестом.

    Расхождение — ошибка, а не предупреждение: набор с непроверенным корнем
    хуже отсутствующего, потому что создаёт видимость доверия.
    """
    directory = directory or DEFAULT_DIR
    manifest_path = os.path.join(directory, "roots.json")
    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
    except OSError as e:
        raise TrustError("набор корней не читается: %s" % e)
    except json.JSONDecodeError as e:
        raise TrustError("roots.json не разбирается: %s" % e)

    if manifest.get("format") != FORMAT:
        raise TrustError("формат набора %r не поддерживается"
                         % manifest.get("format"))
    version = manifest.get("version")
    if not isinstance(version, int) or version < 1:
        raise TrustError("в наборе нет номера версии")

    roots = []
    seen = set()
    for entry in manifest.get("roots", []):
        for key in ("id", "name", "file", "sha256", "source", "obtained"):
            if not entry.get(key):
                raise TrustError("в записи набора нет поля %r: происхождение "
                                 "корня обязано быть указано" % key)
        if entry["id"] in seen:
            raise TrustError("повтор идентификатора корня: %s" % entry["id"])
        seen.add(entry["id"])

        path = os.path.join(directory, entry["file"])
        try:
            with open(path, "rb") as f:
                pem = f.read()
        except OSError as e:
            raise TrustError("корень %s не читается: %s" % (entry["id"], e))

        ders = pem_certs(pem)
        if len(ders) != 1:
            raise TrustError("в %s сертификатов %d, ожидался ровно один"
                             % (entry["file"], len(ders)))
        got = fingerprint(ders[0])
        if got != entry["sha256"]:
            raise TrustError(
                "корень %s: отпечаток файла %s не совпадает с манифестом %s "
                "— набор подменён или манифест устарел"
                % (entry["id"], got, entry["sha256"]))
        roots.append(Root(entry, pem))

    if not roots:
        raise TrustError("набор пуст")
    return Store(version, roots, origin)
