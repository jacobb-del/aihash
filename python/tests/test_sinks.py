"""Сохранность: приёмники, политика хранения, отчёт о пробелах.

Отдельно отмечено, что именно доказывает каждый тест. Про S3 Object Lock тесты
доказывают, что мы запрашиваем верный режим и срок и отказываемся писать в
корзину без блокировки. Что блокировка работает — поведение AWS, и локальным
макетом это не проверяется: moto запоминает режим, но удаление пропускает.
"""

import os
import stat
import subprocess

import pytest

import aihash
from aihash import journal, retention, seal, sinks, store, verify

REALM = "romashka-prod"
STREAM = "voice-eu-3"
GO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "..", "..", "verifier", "dist", "aihash-verify")

EPISODE = [
    {"actor": "customer", "customer.name": "Пётр Ильич Сергеев",
     "input.text": "Когда придёт возврат?"},
    {"actor": "assistant", "output.text": "возврат придёт в течение 5 дней",
     "config.model": "gpt-4o-2026-02-11"},
]


def yesterday():
    return journal.period_of(journal.now_ms() - 86400_000)


@pytest.fixture()
def sealed(tmp_path):
    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 86400_000
    log = aihash.BoundStream(
        journal.Journal(root, REALM, beacon_source=None, clock=lambda: fixed), STREAM)
    for f in EPISODE:
        log.record(f, sync=True)
    log.close()
    layout = store.Layout(root)
    seal.seal_day(layout, REALM, yesterday())
    seal.anchor_day(layout, yesterday(), ["feed"])
    return layout


# --- локальный приёмник -----------------------------------------------------


def test_archive_is_itself_a_valid_journal(sealed, tmp_path):
    """Главное свойство архива: его проверяет тот же верификатор без правок."""
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    res = sinks.archive_date(sealed, [sink], yesterday(),
                             retention.Policy().retain_until(yesterday()))
    assert not res["problems"]
    assert res["artifacts"] >= 5

    r = verify.verify_journal(sink.root)
    assert r.ok, r.problems
    assert r.status == verify.SEALED
    assert r.records == len(EPISODE)


@pytest.mark.skipif(not os.path.exists(GO), reason="нужен собранный бинарь")
def test_go_binary_verifies_the_archive(sealed, tmp_path):
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    sinks.archive_date(sealed, [sink], yesterday(), None)
    r = subprocess.run([GO, sink.root], capture_output=True, timeout=60)
    text = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode == 0, text
    assert "The chain matches end to end" in text


def test_archived_files_are_read_only(sealed, tmp_path):
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    sinks.archive_date(sealed, [sink], yesterday(), None)
    day = os.path.join(sink.root, "days", yesterday() + ".day.json")
    mode = stat.S_IMODE(os.stat(day).st_mode)
    assert not mode & stat.S_IWUSR, "право на запись осталось"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        # Под root снятое право на запись ничего не запрещает: ядро его не
        # проверяет. Само снятие проверено строкой выше — она и есть суть
        # теста. Пропуск нужен, чтобы прогон в контейнере (а он идёт от root)
        # не показывал новому человеку красный тест на исправном коде.
        pytest.skip("под root снятие права на запись не действует")
    with pytest.raises(PermissionError):
        open(day, "w").write("x")


def test_local_sink_admits_what_it_does_not_protect(tmp_path):
    """Приёмник обязан сам говорить о границе своей защиты."""
    d = sinks.LocalArchiveSink(str(tmp_path / "a")).describe()
    assert "не от того, кто владеет каталогом" in d["honest_note"]


def test_verify_copies_catches_a_damaged_archive(sealed, tmp_path):
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    sinks.archive_date(sealed, [sink], yesterday(), None)
    assert sinks.verify_copies(sealed, [sink], yesterday())["ok"]

    day = os.path.join(sink.root, "days", yesterday() + ".day.json")
    os.chmod(day, stat.S_IRUSR | stat.S_IWUSR)
    with open(day, "w") as f:
        f.write("{}")
    chk = sinks.verify_copies(sealed, [sink], yesterday())
    assert not chk["ok"]
    assert any("day.json" in x for x in chk["differs"])


def test_open_day_is_not_archived(sealed, tmp_path):
    """Блокировать на запись можно только то, что уже окончательно."""
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    today = journal.period_of(journal.now_ms())
    with pytest.raises(sinks.SinkError) as e:
        sinks.archive_date(sealed, [sink], today, None)
    assert "не закрыты" in str(e.value)


# --- S3 Object Lock ---------------------------------------------------------


def _s3(lock=True):
    import boto3
    s3 = boto3.client("s3", region_name="eu-central-1")
    kw = dict(Bucket="evidence-test",
              CreateBucketConfiguration={"LocationConstraint": "eu-central-1"})
    if lock:
        kw["ObjectLockEnabledForBucket"] = True
    s3.create_bucket(**kw)
    return s3


def test_s3_refuses_bucket_without_object_lock():
    """Худший исход — клиент считает себя защищённым, не будучи защищённым."""
    from moto import mock_aws
    with mock_aws():
        s3 = _s3(lock=False)
        with pytest.raises(sinks.SinkError) as e:
            sinks.S3ObjectLockSink("evidence-test", client=s3)
        assert "Object Lock" in str(e.value)


def test_s3_sets_compliance_mode_and_retain_date(sealed):
    """Доказывает: мы запрашиваем COMPLIANCE и верную дату.
    Не доказывает: что AWS не даст удалить — это его поведение, не наше."""
    from moto import mock_aws
    with mock_aws():
        s3 = _s3()
        sink = sinks.S3ObjectLockSink("evidence-test", prefix="romashka", client=s3)
        until = retention.Policy(years=7).retain_until(yesterday())
        res = sinks.archive_date(sealed, [sink], yesterday(), until)
        assert not res["problems"]
        for w in res["written"]:
            assert w["lock_mode"] == "COMPLIANCE"

        key = "romashka/days/%s.day.json" % yesterday()
        head = s3.head_object(Bucket="evidence-test", Key=key)
        assert head["ObjectLockMode"] == "COMPLIANCE"
        assert head["ObjectLockRetainUntilDate"].year == until.year
        assert sinks.verify_copies(sealed, [sink], yesterday())["ok"]


def test_s3_sink_admits_who_enforces(sealed):
    from moto import mock_aws
    with mock_aws():
        d = sinks.S3ObjectLockSink("evidence-test", client=_s3()).describe()
    assert d["enforced_by"] == "AWS S3 Object Lock"
    assert "не эта библиотека" in d["honest_note"]


# --- политика и отчёт -------------------------------------------------------


def test_retain_until_counts_from_the_day_not_from_archiving(tmp_path):
    """Отсчёт от суток: иначе поздняя укладка незаметно продлевала бы срок и
    прятала просрочку."""
    p = retention.Policy(years=7)
    assert p.retain_until("2026-03-12").date().isoformat() == "2033-03-12"
    assert p.retain_until("2024-02-29").date().isoformat() == "2031-02-28"


def test_status_reports_gaps(sealed, tmp_path):
    st = retention.status(sealed)
    assert st["archived"] == []
    assert yesterday() in st["overdue_archive"]
    assert not st["ok"], "незалолженные сутки — это пробел, а не норма"

    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    retention.save(sealed, retention.Policy(7, "COMPLIANCE", ["local:" + sink.root]))
    res = sinks.archive_date(sealed, [sink], yesterday(), None)
    retention.write_receipt(sealed, yesterday(), res)

    st = retention.status(sealed)
    assert st["archived"] == [yesterday()]
    assert st["overdue_archive"] == []
    assert st["ok"]
    text = retention.format_report(st)
    assert "хранить 7 лет" in text
    assert "Пробелов нет" in text


def test_status_flags_unsealed_past_day(tmp_path):
    """Тот самый сценарий: сутки прошли, а закрыть их забыли."""
    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 3 * 86400_000
    log = aihash.BoundStream(
        journal.Journal(root, REALM, beacon_source=None, clock=lambda: fixed), STREAM)
    log.record({"actor": "system", "x": "1"}, sync=True)
    log.close()
    st = retention.status(store.Layout(root))
    assert st["overdue_seal"] == [journal.period_of(fixed)]
    assert not st["ok"]
    assert "ПРОСРОЧЕНО закрытие" in retention.format_report(st)


def test_policy_rejects_meaningless_term():
    with pytest.raises(Exception):
        retention.Policy(years=0)


# --- конфликт вычёркивания и неизменяемого хранения -------------------------


def test_redaction_does_not_reach_the_archive_by_itself(sealed, tmp_path):
    """Вычёркивание правит журнал, но не копию в архиве. Клиент, применивший
    обе возможности как написано в документации, обязан узнать об этом от нас,
    а не от проверяющего органа."""
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    res = sinks.archive_date(sealed, [sink], yesterday(), None)
    retention.write_receipt(sealed, yesterday(), res)
    assert b"\xd0\xa1\xd0\xb5\xd1\x80\xd0\xb3\xd0\xb5\xd0\xb5\xd0\xb2" in \
        open(os.path.join(sink.root, "streams", STREAM, "segments",
                          yesterday() + ".jsonl"), "rb").read()

    j = journal.Journal(sealed.root, REALM, beacon_source=None)
    j.stream(STREAM).redact(1, ["customer.name"], "запрос на удаление")
    j.close()

    archived = open(os.path.join(sink.root, "streams", STREAM, "segments",
                                 yesterday() + ".jsonl"), "rb").read()
    assert "Сергеев".encode("utf-8") in archived, \
        "если это перестало быть правдой — обновите предупреждение и документацию"

    # Переукладка доводит вычёркивание туда, где удаление вообще возможно.
    sinks.archive_date(sealed, [sink], yesterday(), None)
    archived = open(os.path.join(sink.root, "streams", STREAM, "segments",
                                 yesterday() + ".jsonl"), "rb").read()
    assert "Сергеев".encode("utf-8") not in archived
    assert verify.verify_journal(sink.root).ok


def test_cli_warns_and_names_the_remedy(sealed, tmp_path, capsys):
    from aihash import cli
    sink = sinks.LocalArchiveSink(str(tmp_path / "archive"))
    retention.write_receipt(sealed, yesterday(),
                            sinks.archive_date(sealed, [sink], yesterday(), None))
    capsys.readouterr()
    rc = cli.main(["redact", "--root", sealed.root, "--stream", STREAM,
                   "--seq", "1", "--fields", "customer.name",
                   "--reason", "запрос на удаление"])
    err = capsys.readouterr().err
    assert "уже уложены в архив" in err
    assert "--force" in err, "предупреждение обязано называть точную команду"
    assert rc == 0, "для приёмника без блокировки исправление возможно"


def test_compliance_mode_is_reported_as_impossible(sealed, tmp_path, capsys):
    """Для хранилища с блокировкой удаление невозможно в принципе, и команда
    обязана вернуть ненулевой код, а не сделать вид, что всё в порядке."""
    from aihash import cli
    retention.write_receipt(sealed, yesterday(), {
        "date": yesterday(), "artifacts": 1,
        "written": [{"sink": "s3", "key": "x", "lock_mode": "COMPLIANCE"}]})
    capsys.readouterr()
    rc = cli.main(["redact", "--root", sealed.root, "--stream", STREAM,
                   "--seq", "1", "--fields", "customer.name", "--reason", "у"])
    err = capsys.readouterr().err
    assert "COMPLIANCE" in err
    assert "не исполняется" in err
    assert rc == 1
