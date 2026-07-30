"""Сквозные проверки журнала: запись, вычёркивание, пломба, пакет, подделка."""

import json
import os
import threading
import zipfile

import pytest

import aihash
from aihash import bundle, cli, core, journal, seal, store, verify

REALM = "romashka-prod"
STREAM = "voice-eu-3"

EPISODE = [
    {"actor": "customer", "customer.name": "Пётр Ильич Сергеев",
     "customer.phone": "+7 916 555-01-72",
     "input.text": "Когда придёт возврат за отменённый заказ?"},
    {"actor": "assistant", "tool.name": "orders.get",
     "tool.result": '{"order":"A-40912","status":"cancelled"}'},
    {"actor": "assistant", "output.text": "возврат придёт в течение 5 дней",
     "config.prompt_version": "v14", "config.model": "gpt-4o-2026-02-11",
     "config.human_review": ""},
    {"actor": "system", "billing.op": "RF-88214"},
]


@pytest.fixture()
def root(tmp_path):
    return str(tmp_path / "journal")


def today():
    return journal.period_of(journal.now_ms())


def yesterday():
    return journal.period_of(journal.now_ms() - 86400_000)


def write_episode(root, beacon=None, day=None):
    """day=None — пишем текущими сутками; иначе часы подменяются.

    Подмена нужна там, где проверяется пломба: закрывать можно только
    завершившиеся сутки, поэтому эпизод должен лежать во вчерашнем отрезке.
    """
    clock = None
    if day is not None:
        fixed = journal.now_ms() - 86400_000
        clock = lambda: fixed  # noqa: E731
    log = aihash.BoundStream(
        journal.Journal(root, REALM, beacon_source=beacon, clock=clock), STREAM)
    seqs = [log.record(f, sync=True) for f in EPISODE]
    log.close()
    return seqs


# --- запись -----------------------------------------------------------------


def test_write_and_verify(root):
    seqs = write_episode(root)
    assert seqs == [1, 2, 3, 4]
    r = verify.verify_journal(root)
    assert r.ok, r.problems
    assert r.records == 4
    assert r.status == verify.OPEN, "без пломбы состояние не может быть sealed"


def test_resume_continues_chain(root):
    write_episode(root)
    log = aihash.open(root, realm=REALM, stream=STREAM, beacon_source=None)
    assert log.record({"actor": "system", "note": "после перезапуска"},
                      sync=True) == 5
    log.close()
    assert verify.verify_journal(root).ok


def test_async_returns_no_seq(root):
    """В асинхронном режиме номер ещё не присвоен, и выдумывать его нельзя."""
    log = aihash.open(root, realm=REALM, stream=STREAM, beacon_source=None)
    assert log.record({"actor": "system", "x": "1"}) is None
    log.flush()
    log.close()
    assert verify.verify_journal(root).records == 1


def test_reserved_prefix_rejected(root):
    log = aihash.open(root, realm=REALM, stream=STREAM, beacon_source=None)
    with pytest.raises(core.FormatError):
        log.record({"_beacon.round": "1"})
    log.close()


def test_overflow_is_loud_not_silent(root):
    """Тихо сбросить событие доказательственный журнал не вправе."""
    j = journal.Journal(root, REALM, queue_size=2, put_timeout=0.01,
                        flush_interval=60.0, beacon_source=None)
    s = j.stream(STREAM)
    gate = threading.Event()
    original = s._write
    s._write = lambda item: (gate.wait(10.0), original(item))[1]
    try:
        with pytest.raises(journal.Overflow):
            for _ in range(50):
                s.record({"actor": "system", "x": "1"})
    finally:
        gate.set()
        j.close()


# --- вычёркивание -----------------------------------------------------------


def test_redaction_keeps_seal(root):
    write_episode(root)
    layout = store.Layout(root)
    before = [r for r in layout.read_segment(STREAM, today()) if r["seq"] == 1][0]
    croot_before = before["content_root"]

    log = aihash.open(root, realm=REALM, stream=STREAM, beacon_source=None)
    ev = log.redact(1, ["customer.name", "customer.phone"],
                    "запрос на удаление персональных данных")
    log.close()

    after = [r for r in layout.read_segment(STREAM, today()) if r["seq"] == 1][0]
    assert after["content_root"] == croot_before, "отпечаток изменился"

    names = {f["name"]: f for f in after["fields"]}
    for n in ("customer.name", "customer.phone"):
        assert "leaf" in names[n]
        assert "salt" not in names[n] and "s" not in names[n]
    assert "Сергеев" not in json.dumps(after, ensure_ascii=False)

    ev_rec = [r for r in layout.read_segment(STREAM, today()) if r["seq"] == ev][0]
    ev_names = {f["name"]: f["s"] for f in ev_rec["fields"]}
    assert ev_names["_redaction.target_seq"] == "1"
    assert "удаление" in ev_names["_redaction.reason"]

    r = verify.verify_journal(root)
    assert r.ok, r.problems
    assert r.streams[0]["redacted"] == 2


def test_redaction_after_sealing_survives(root):
    """Главное свойство: вычеркнуть можно и после постановки пломбы."""
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    assert verify.verify_journal(root).status == verify.SEALED

    log = aihash.open(root, realm=REALM, stream=STREAM, beacon_source=None)
    log.redact(1, ["customer.name"], "запрос на удаление")
    log.close()

    r = verify.verify_journal(root)
    assert r.ok, r.problems
    assert r.status == verify.SEALED, "вычёркивание сорвало пломбу"


def test_open_writer_refuses_segment_sealed_underneath(root):
    """Пломбу ставит отдельный процесс по расписанию. Долгоживущий писатель не
    вправе дописывать в отрезок, запечатанный у него под руками."""
    fixed = journal.now_ms() - 86400_000
    j = journal.Journal(root, REALM, beacon_source=None, clock=lambda: fixed)
    s = j.stream(STREAM)
    s.record({"actor": "system", "x": "1"}, sync=True)
    s.flush()
    seal.seal_day(store.Layout(root), REALM, yesterday())
    with pytest.raises(Exception) as e:
        s.record({"actor": "system", "x": "2"}, sync=True)
    assert "запечатан" in str(e.value)
    j.close()
    assert verify.verify_journal(root).ok, "журнал повреждён дописыванием"


# --- пломба и пакет ---------------------------------------------------------


def test_seal_and_bundle(root, tmp_path):
    write_episode(root, day="past")
    layout = store.Layout(root)
    day = seal.seal_day(layout, REALM, yesterday())
    assert day["streams"] == [STREAM]
    res = seal.anchor_day(layout, yesterday(), ["feed"])
    assert res[0]["ok"] and res[0]["published"] is False

    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)
    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
    for req in ("manifest.json", "records.jsonl", "proofs.json", "segment.json",
                "day.json", "report.html", "VERIFY.txt"):
        assert req in names

    r = verify.verify_bundle(out)
    assert r["status"] == verify.SEALED, r["problems"]
    assert r["manifest"]["disclosed_of_total"] == [1, 4]


def test_bundle_hides_other_records(root, tmp_path):
    """Отдавать оппоненту весь журнал юридически неприемлемо."""
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)
    with zipfile.ZipFile(out) as z:
        blob = z.read("records.jsonl").decode("utf-8") + z.read("report.html").decode("utf-8")
    assert "возврат придёт" in blob
    assert "Сергеев" not in blob
    assert "RF-88214" not in blob


def test_report_states_what_is_not_proved(root, tmp_path):
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)
    with zipfile.ZipFile(out) as z:
        html = z.read("report.html").decode("utf-8")
    assert "не подтверждает" in html
    assert "до поля" in html, "нет оговорки про локализацию расхождения"


def test_report_draws_no_interval_without_a_beacon(root, tmp_path):
    """Односторонняя граница — не интервал. Шкала с двумя засечками без маяка
    показывала бы больше, чем доказано, — в документе, который идёт в спор."""
    write_episode(root, day="past")          # beacon_source=None
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)
    with zipfile.ZipFile(out) as z:
        html = z.read("report.html").decode("utf-8")
    assert 'class="bar"' not in html, "нарисован интервал, которого нет"
    assert "Известна только верхняя граница" in html


def test_report_draws_the_interval_when_a_beacon_exists(root, tmp_path):
    from aihash import report
    manifest = {"format": "aihash/1", "hash": "sha256", "realm_id": REALM,
                "stream_id": STREAM, "period_id": "2026-07-28", "seqs": [1],
                "created": 0, "disclosed_of_total": [1, 1],
                "beacon": {"source": "drand:quicknet", "round": "30837112", "seq": 1}}
    rec = {"seq": 1, "ts": 1785000000000,
           "fields": [{"name": "actor", "salt": "00" * 16, "s": "assistant"}],
           "content_root": "aa" * 32, "link": "bb" * 32}
    seg = {"period_id": "2026-07-28", "first_seq": 1, "last_seq": 1, "count": 1,
           "segment_root": "cc" * 32, "checkpoint": "dd" * 32}
    day = {"day_root": "ee" * 32, "day_checkpoint": "ff" * 32}
    html = report.render(manifest, [rec], seg, day, ["2026-07-28.rfc3161.tsr"])
    assert 'class="bar"' in html
    assert "не раньше" in html and "не позже пломбы" in html


def test_unanchored_day_is_open_not_broken(root):
    """Сутки, пломба на которые не встала (лежала сеть), — это «не запечатано»,
    а не «подделано». Обвинение за чужой отказ — худший отказ верификатора."""
    for back in (2, 1):
        fixed = journal.now_ms() - back * 86400_000
        j = journal.Journal(root, REALM, beacon_source=None, clock=lambda f=fixed: f)
        j.stream(STREAM).record({"actor": "system", "x": "1"}, sync=True)
        j.close()
    layout = store.Layout(root)
    days = layout.periods(STREAM)
    for d in days:
        seal.seal_day(layout, REALM, d)
    seal.anchor_day(layout, days[1], ["feed"])   # первые сутки остались без пломбы

    r = verify.verify_journal(root)
    assert r.ok, r.problems
    by_date = {d["date"]: d["status"] for d in r.days}
    assert by_date[days[0]] == verify.OPEN, "незапечатанные сутки объявлены подделкой"
    assert by_date[days[1]] == verify.SEALED


def test_broken_feed_is_still_broken(root):
    """Порванная лента — это уже подделка, и мягчить её нельзя."""
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
    e = json.loads(open(feed, encoding="utf-8").read().strip())
    e["prev"] = "11" * 32
    open(feed, "w", encoding="utf-8").write(json.dumps(e) + "\n")
    assert not verify.verify_journal(root).ok


def test_opening_a_long_journal_does_not_read_it_all(root):
    """Пишущему нужен только кончик цепи. Чтение всей истории превращало бы
    запуск процесса в минуты на журнале за несколько лет."""
    for back in (3, 2, 1):
        fixed = journal.now_ms() - back * 86400_000
        j = journal.Journal(root, REALM, beacon_source=None, clock=lambda f=fixed: f)
        s = j.stream(STREAM)
        for i in range(20):
            s.record({"actor": "system", "i": str(i)})
        j.close()

    reads = []
    original = store.Layout.read_segment
    store.Layout.read_segment = lambda self, sid, p: (reads.append(p) or
                                                      original(self, sid, p))
    try:
        j = journal.Journal(root, REALM, beacon_source=None)
        assert j.stream(STREAM).record({"actor": "system", "z": "1"},
                                       sync=True) == 61
        j.close()
    finally:
        store.Layout.read_segment = original
    assert reads == [], "при открытии журнала прочитаны отрезки: %s" % reads


def test_truncated_tail_is_refused_loudly(root):
    """Падение посреди записи оставляет оборванную строку. Дописывать после
    неё нельзя: получится запись, которую не проверить."""
    j = journal.Journal(root, REALM, beacon_source=None)
    s = j.stream(STREAM)
    s.record({"actor": "system", "x": "1"}, sync=True)
    s.record({"actor": "system", "x": "2"}, sync=True)
    j.close()
    path = store.Layout(root).segment_file(STREAM, today())
    data = open(path, "rb").read()
    open(path, "wb").write(data[:-20])
    with pytest.raises(core.FormatError) as e:
        journal.Journal(root, REALM, beacon_source=None).stream(STREAM)
    assert "оборвана" in str(e.value)


# --- подделка ---------------------------------------------------------------


def _tamper(root, seq, name, new_value, period=None):
    layout = store.Layout(root)
    period = period or yesterday()
    recs = layout.read_segment(STREAM, period)
    for rec in recs:
        if rec["seq"] == seq:
            for f in rec["fields"]:
                if f["name"] == name:
                    f["s"] = new_value
    path = layout.segment_file(STREAM, period)
    with open(path, "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")


def test_edited_word_is_caught(root):
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    _tamper(root, 3, "output.text", "возврат придёт в течение 5 рабочих дней")
    r = verify.verify_journal(root)
    assert not r.ok
    assert "seq=3" in r.problems[0]


def test_deleted_record_is_caught(root):
    write_episode(root)
    layout = store.Layout(root)
    path = layout.segment_file(STREAM, today())
    lines = open(path, encoding="utf-8").read().splitlines()
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines[:1] + lines[2:]) + "\n")
    r = verify.verify_journal(root)
    assert not r.ok
    assert "пропуск" in r.problems[0]


def test_tampered_bundle_is_caught(root, tmp_path):
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)

    edited = str(tmp_path / "edited.seal")
    with zipfile.ZipFile(out) as zin, zipfile.ZipFile(edited, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "records.jsonl":
                data = data.replace("5 дней".encode(), "5 раб.".encode())
            zout.writestr(item, data)

    r = verify.verify_bundle(edited)
    assert r["status"] == verify.BROKEN
    assert any("seq=3" in p for p in r["problems"])


def test_feed_break_is_caught(root):
    write_episode(root, day="past")
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
    lines = open(feed, encoding="utf-8").read().splitlines()
    e = json.loads(lines[0])
    e["target"] = "00" * 32
    open(feed, "w", encoding="utf-8").write(json.dumps(e) + "\n")
    r = verify.verify_journal(root)
    assert not r.ok


# --- командная строка -------------------------------------------------------


def test_cli_flow(root, tmp_path, capsys):
    write_episode(root, day="past")
    assert cli.main(["seal", "--root", root, "--anchor", "feed"]) == 0
    out = str(tmp_path / "ep.seal")
    assert cli.main(["explain", "--root", root, "--stream", STREAM,
                     "--seq", "3", "--out", out]) == 0
    capsys.readouterr()
    assert cli.main(["verify", out]) == 0
    text = capsys.readouterr().out
    assert "не ранее" in text or "суточное дерево" in text
    assert cli.main(["ls", "--root", root]) == 0


def test_cli_verify_reports_broken(root, capsys):
    write_episode(root)
    _tamper(root, 3, "output.text", "другое", period=today())
    assert cli.main(["verify", root]) == 1
    text = capsys.readouterr().out
    assert "НЕ СХОДИТСЯ" in text
