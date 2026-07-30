"""Разложить набор корней из spec/trust/ по реализациям.

Тот же приём, каким verifier/build.py кладёт verify.html в SDK: источник истины
один, копии генерируются. Сборка обязана падать при расхождении отпечатка —
иначе корень подменяется правкой файла, а корень это то, чему верит получатель.

    python3 spec/tools/buildtrust.py

Пока разложить есть куда только в Python: остальные реализации подпись штампа
не проверяют вовсе. Когда появится разбор RFC 3161 в Go, сюда добавится
генерация trust.gen.go.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import trust  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
PY_ASSET = os.path.join(REPO, "python", "aihash", "assets", "trust.json")


def bundle(store: trust.Store) -> dict:
    """Один файл вместо каталога: получателю SDK нечего обходить, а проверка
    отпечатка при загрузке остаётся возможной — PEM лежит рядом с ним."""
    return {
        "format": trust.FORMAT,
        "version": store.version,
        "roots": [
            {"id": r.id, "name": r.name, "sha256": r.sha256,
             "subject": r.subject, "source": r.source,
             "not_after": r.not_after,
             "pem": r.pem.decode("ascii")}
            for r in store.roots
        ],
    }


def main() -> int:
    try:
        store = trust.load()
    except trust.TrustError as e:
        print("набор корней не принят: %s" % e, file=sys.stderr)
        return 1

    data = json.dumps(bundle(store), ensure_ascii=False, indent=2) + "\n"
    os.makedirs(os.path.dirname(PY_ASSET), exist_ok=True)
    with open(PY_ASSET, "w", encoding="utf-8") as f:
        f.write(data)

    print("набор корней %d, корней в нём %d" % (store.version, len(store)))
    for r in store.roots:
        print("  %-10s %s… до %s" % (r.id, r.sha256[:24], r.not_after or "—"))
    print("уложено: python/aihash/assets/trust.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
