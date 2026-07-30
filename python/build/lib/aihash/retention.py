"""Политика хранения и отчёт о сохранности.

Первое сообщение продукта — «ваши записи о работе ИИ исчезают через 30 дней;
когда придёт запрос, показывать будет нечего». Команда `aihash retention`
отвечает на него цифрами: с какого числа записи есть, что запечатано, что
уложено в архив и до какого года защищено.
"""

from __future__ import annotations

import datetime as dt
import os
from typing import List, Optional

from . import core, store

POLICY_FILE = "retention.json"
DEFAULT_YEARS = 7


class Policy:
    """Сколько лет держим и в каком режиме."""

    def __init__(self, years: int = DEFAULT_YEARS, mode: str = "COMPLIANCE",
                 sinks: Optional[List[str]] = None):
        if years < 1:
            raise core.FormatError("срок хранения меньше года лишён смысла")
        self.years = years
        self.mode = mode
        self.sinks = sinks or []

    def retain_until(self, date: str) -> dt.datetime:
        """Дата, до которой сутки обязаны сохраняться. Отсчёт от самих суток,
        а не от момента архивации: иначе поздняя укладка в архив незаметно
        продлевала бы срок и прятала просрочку."""
        d = dt.datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
        try:
            return d.replace(year=d.year + self.years)
        except ValueError:  # 29 февраля
            return d.replace(month=2, day=28, year=d.year + self.years)

    def to_dict(self) -> dict:
        return {"format": core.FORMAT_VERSION, "years": self.years,
                "mode": self.mode, "sinks": self.sinks}


def load(layout: store.Layout) -> Optional[Policy]:
    path = os.path.join(layout.root, POLICY_FILE)
    if not os.path.exists(path):
        return None
    d = store.read_json(path)
    return Policy(d.get("years", DEFAULT_YEARS), d.get("mode", "COMPLIANCE"),
                  d.get("sinks", []))


def save(layout: store.Layout, policy: Policy) -> None:
    store.write_json(os.path.join(layout.root, POLICY_FILE), policy.to_dict())


# --- квитанции об архивации -------------------------------------------------


def receipt_path(layout: store.Layout, date: str) -> str:
    return os.path.join(layout.root, "archive", "%s.archive.json" % date)


def write_receipt(layout: store.Layout, date: str, result: dict) -> None:
    path = receipt_path(layout, date)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    store.write_json(path, result)


def read_receipt(layout: store.Layout, date: str) -> Optional[dict]:
    path = receipt_path(layout, date)
    return store.read_json(path) if os.path.exists(path) else None


def archived_sinks(layout: store.Layout, date: str) -> List[dict]:
    """Куда уже уложены эти сутки. Нужно вычёркиванию: копию в архиве оно само
    не достаёт, и молчать об этом нельзя."""
    r = read_receipt(layout, date)
    if not r:
        return []
    seen, out = set(), []
    for w in r.get("written", []):
        key = (w.get("sink"), w.get("lock_mode"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"sink": w.get("sink"), "lock_mode": w.get("lock_mode")})
    return out


# --- отчёт ------------------------------------------------------------------


def status(layout: store.Layout, now: Optional[dt.datetime] = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    policy = load(layout)

    dates = set()
    for stream_id in layout.streams():
        dates.update(layout.periods(stream_id))
    dates = sorted(dates)

    sealed = set(layout.dates())
    archived, unarchived, receipts = [], [], {}
    for d in dates:
        r = read_receipt(layout, d)
        if r and not r.get("problems"):
            archived.append(d)
            receipts[d] = r
        else:
            unarchived.append(d)

    today = now.strftime("%Y-%m-%d")
    out = {
        "realm_id": layout.realm().get("realm_id") if
        os.path.exists(layout.realm_file) else None,
        "policy": policy.to_dict() if policy else None,
        "days_total": len(dates),
        "first_day": dates[0] if dates else None,
        "last_day": dates[-1] if dates else None,
        "sealed": sorted(sealed),
        "not_sealed": [d for d in dates if d not in sealed],
        "archived": archived,
        "not_archived": unarchived,
        "current_day": today,
    }

    # Просрочка — сутки, которые давно закончились, но так и не уложены.
    # Именно она превращается в «показывать нечего», когда придёт запрос.
    out["overdue_seal"] = [d for d in out["not_sealed"] if d < today]
    out["overdue_archive"] = [d for d in unarchived if d in sealed]

    if policy and archived:
        out["protected_until"] = policy.retain_until(min(archived)).date().isoformat()
        out["sinks_used"] = sorted({w["sink"] for d in archived
                                    for w in receipts[d].get("written", [])})
    out["ok"] = not out["overdue_seal"] and not out["overdue_archive"]
    return out


def format_report(st: dict) -> str:
    lines = []
    lines.append("Журнал %s" % (st["realm_id"] or "?"))
    p = st["policy"]
    if p:
        lines.append("  Политика: хранить %d лет, режим %s"
                     % (p["years"], p["mode"].lower()))
    else:
        lines.append("  Политика хранения не задана — aihash retention --set-years N")

    if not st["days_total"]:
        lines.append("  Записей нет")
        return "\n".join(lines)

    lines.append("  Записи с %s по %s (%d суток)"
                 % (st["first_day"], st["last_day"], st["days_total"]))
    lines.append("  Запечатано: %d суток" % len(st["sealed"]))
    if st["archived"]:
        lines.append("  В архиве:   %d суток, приёмники: %s"
                     % (len(st["archived"]), ", ".join(st.get("sinks_used", []))))
        if st.get("protected_until"):
            lines.append("              самая ранняя запись защищена до %s"
                         % st["protected_until"])
    else:
        lines.append("  В архиве:   ничего")

    today = st["current_day"]
    running = [d for d in st["not_sealed"] if d >= today]
    if running:
        lines.append("  Не запечатано: %s — сутки ещё идут" % ", ".join(running))
    if st["overdue_seal"]:
        lines.append("  ПРОСРОЧЕНО закрытие: %s" % ", ".join(st["overdue_seal"]))
    if st["overdue_archive"]:
        lines.append("  ПРОСРОЧЕНА укладка в архив: %s"
                     % ", ".join(st["overdue_archive"]))
    if st["ok"]:
        lines.append("  Пробелов нет: всё завершившееся закрыто и уложено.")
    return "\n".join(lines)
