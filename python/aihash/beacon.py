"""Публичный маяк — нижняя граница времени.

Значение раунда невозможно было знать заранее, поэтому всё, что стоит в цепи
после записи маяка, создано после его публикации. Вместе с пломбой это даёт
двустороннюю границу: не раньше маяка, не позже пломбы.

Недоступность маяка не является ошибкой: отрезок пишется без него, нижней
границы в выписке просто не будет.
"""

from __future__ import annotations

import json
import time
import urllib.request
from typing import Optional

DRAND_QUICKNET = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
DRAND_URL = "https://api.drand.sh/%s/public/latest" % DRAND_QUICKNET

SOURCES = {
    "drand": ("drand:quicknet", DRAND_URL),
}


def fetch(source: str = "drand", timeout: float = 2.0) -> Optional[dict]:
    entry = SOURCES.get(source)
    if entry is None:
        return None
    name, url = entry
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        return {"source": name,
                "round": int(data["round"]),
                "value": bytes.fromhex(data["randomness"]),
                "signature": data.get("signature", ""),
                "fetched_at": int(time.time() * 1000)}
    except Exception:
        return None


def lower_bound_ms(round_no: int, source: str = "drand:quicknet") -> Optional[int]:
    """Время публикации раунда. Для quicknet: генезис 1692803367, шаг 3 с.

    Это единственное, что нужно знать проверяющему офлайн, чтобы превратить
    номер раунда во время. Полная проверка подписи BLS выходит за рамки версии
    1 и отмечена в выписке как непроверенная.
    """
    if source != "drand:quicknet":
        return None
    return (1692803367 + (round_no - 1) * 3) * 1000
