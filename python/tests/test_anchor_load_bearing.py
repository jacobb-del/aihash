"""Штамп третьей стороны — несущий, а не декоративный.

Единственный тест, который это доказывает. Если он перестанет проходить,
защита сводится к нашему собственному коду: противник, у которого есть
исходники, пересчитает журнал целиком, и внутренние проверки промолчат.

Заготовка — не самодельная пломба, а НАСТОЯЩИЙ ответ службы штампов времени
freetsa.org, полученный один раз и уложенный в spec/fixtures/sealed-journal.
Внутренней пломбы feed там нет вовсе: остаётся только внешний якорь, чтобы
проверялся именно он.

Доказательство строится из трёх частей, и каждая нужна:

  1. Положительный путь: журнал и штамп сходятся.
  2. Контроль: подделка внутренне БЕЗУПРЕЧНА — без штампа она проходит
     проверку. Без этой части тест не отличал бы «поймал штамп» от «поймала
     цепь».
  3. Отрицательный путь: со штампом та же подделка отвергается.
"""

import glob
import json
import os
import shutil
import subprocess

import pytest

import faketsa
from aihash import core, journal, store, verify

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
FIXTURE = os.path.join(REPO, "spec", "fixtures", "sealed-journal")
GO = os.path.join(REPO, "verifier", "dist", "aihash-verify")
TS = os.path.join(REPO, "typescript", "dist", "src", "cli.js")

has_fixture = os.path.exists(os.path.join(FIXTURE, "meta.json"))
pytestmark = pytest.mark.skipif(
    not has_fixture,
    reason="нет фикстуры spec/fixtures/sealed-journal с настоящим штампом")

META = json.load(open(os.path.join(FIXTURE, "meta.json"), encoding="utf-8")) \
    if has_fixture else {}
CA = os.path.join(FIXTURE, META.get("ca", "freetsa-cacert.pem"))


def _runnable(cmd) -> bool:
    """Запускается ли эта реализация ЗДЕСЬ.

    Наличия файла и бита запуска мало: в verifier/dist может лежать бинарь под
    другую систему или архитектуру, и тогда тест падает с «Exec format error»
    вместо честного пропуска. Поймано кросс-машинным прогоном.
    """
    try:
        subprocess.run(list(cmd) + ["--version"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _external():
    out = []
    if os.path.exists(GO) and os.access(GO, os.X_OK) and _runnable([GO]):
        out.append(("Go", [GO]))
    node = shutil.which("node")
    if node and os.path.exists(TS) and _runnable([node, TS]):
        out.append(("TypeScript", [node, TS, "verify"]))
    return out


EXTERNAL = _external()


def _run(cmd, path):
    r = subprocess.run(cmd + [path], capture_output=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


@pytest.fixture()
def sealed(tmp_path):
    """Копия фикстуры: сам каталог тесты не трогают."""
    root = str(tmp_path / "journal")
    shutil.copytree(os.path.join(FIXTURE, "journal"), root)
    return root


def _fingerprint_of(pem_path: str) -> str:
    from aihash import trust as trust_mod
    with open(pem_path, "rb") as f:
        return trust_mod.fingerprint(trust_mod.pem_certs(f.read())[0])


def tsr_path(root):
    found = glob.glob(os.path.join(root, "anchors", "*.rfc3161.tsr"))
    assert len(found) == 1, "в фикстуре должен быть ровно один штамп"
    return found[0]


def forge(root):
    """Пересоздать журнал заново с другим содержимым так, чтобы новая цепь была
    внутренне безупречной: отпечатки полей, звенья, корень отрезка, отметка
    отрезка и суточная отметка — всё пересчитано и согласовано.

    Ровно это и сделает противник, у которого есть исходный код. Слабая
    подделка ничего не проверяет.
    """
    layout = store.Layout(root)
    date, stream, realm = META["date"], META["stream_id"], META["realm_id"]
    recs = layout.read_segment(stream, date)
    assert len(recs) == META["records"]

    prev = core.genesis(stream)
    links = []
    for rec in recs:
        for f in rec["fields"]:
            if f["name"] == "output.text":
                f["salt"] = core.new_salt().hex()
                f["s"] = "возврат НЕ придёт, отказано (запись %d)" % rec["seq"]
        croot = core.content_root(store.fields_for_root(rec["fields"]))
        rec["content_root"] = croot.hex()
        prev = core.link(prev, rec["seq"], croot, rec["ts"])
        rec["link"] = prev.hex()
        links.append(prev)

    with open(layout.segment_file(stream, date), "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(store.record_line(rec["seq"], rec["ts"], rec["fields"],
                                      bytes.fromhex(rec["content_root"]),
                                      bytes.fromhex(rec["link"])) + "\n")

    n = len(recs)
    seg_root = core.seg_root(links)
    seg_ck = core.seg_ckpt(stream, date, 1, n, n, core.genesis(stream),
                           links[-1], seg_root, core.ZERO32)
    store.write_json(layout.segment_ckpt_file(stream, date), {
        "format": core.FORMAT_VERSION, "stream_id": stream, "period_id": date,
        "first_seq": 1, "last_seq": n, "count": n,
        "link_before": core.genesis(stream).hex(), "link_last": links[-1].hex(),
        "segment_root": seg_root.hex(), "prev_checkpoint": core.ZERO32.hex(),
        "checkpoint": seg_ck.hex()})

    day_root = core.day_root([seg_ck])
    day_ck = core.day_ckpt(realm, date, 1, day_root, core.ZERO32)
    store.write_json(layout.day_file(date), {
        "format": core.FORMAT_VERSION, "realm_id": realm, "date": date,
        "streams": [stream], "segment_checkpoints": [seg_ck.hex()],
        "day_root": day_root.hex(), "prev_checkpoint": core.ZERO32.hex(),
        "day_checkpoint": day_ck.hex()})
    return day_ck.hex()


# --- 1. положительный путь: журнал и настоящий штамп сходятся ---------------


def test_pristine_journal_with_real_stamp_verifies(sealed):
    """Автоматически, офлайн, без самодельной пломбы: единственный якорь —
    настоящий ответ freetsa.org."""
    assert not os.path.exists(
        os.path.join(sealed, "anchors", "feed.jsonl")), \
        "в фикстуре не должно быть внутренней пломбы — иначе проверяется она"

    r = verify.verify_journal(sealed, {"tsa_ca": CA})
    assert r.ok, r.problems
    assert r.status == verify.SEALED, "журнал с проверенным штампом не запечатан"
    assert r.records == META["records"]

    anchors = [a for d in r.days for a in d["anchors"]]
    assert len(anchors) == 1 and anchors[0]["type"] == "rfc3161"
    assert anchors[0]["status"] == "ok", anchors[0]
    assert META["tsa_time"] in (anchors[0].get("time") or "")


def test_stamp_covers_exactly_this_day_checkpoint(sealed):
    """Штамп заверяет именно ту суточную отметку, которая лежит в журнале."""
    day = store.Layout(sealed).read_day(META["date"])
    assert day["day_checkpoint"] == META["day_checkpoint"]
    with open(tsr_path(sealed), "rb") as f:
        assert bytes.fromhex(day["day_checkpoint"]) in f.read()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="нужен openssl")
def test_third_party_tool_agrees(sealed):
    """Подпись проверяется чужим инструментом, а не нашим кодом."""
    day = store.Layout(sealed).read_day(META["date"])
    r = subprocess.run(["openssl", "ts", "-verify",
                        "-digest", day["day_checkpoint"],
                        "-in", tsr_path(sealed), "-CAfile", CA],
                       capture_output=True, timeout=60)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode == 0, out
    assert "Verification: OK" in out, out


def test_one_command_verifies_from_the_embedded_root_store(sealed, capsys):
    """Одна команда, без `--tsa-ca`: подпись сверяется вшитым набором корней.

    Это и есть смысл переноса корня доверия в верификатор. Раньше получатель
    обязан был где-то раздобыть cacert.pem, и до тех пор исправный журнал
    выглядел неподтверждённым.
    """
    r = verify.verify_journal(sealed)          # именно без tsa_ca
    assert r.ok, r.problems
    assert r.status == verify.SEALED, "вшитый набор корней не сработал"
    anchors = [a for d in r.days for a in d["anchors"]]
    assert len(anchors) == 1 and anchors[0]["status"] == "ok"
    assert anchors[0]["root"]["id"] == "freetsa"

    from aihash import cli
    assert cli.main(["verify", sealed]) == 0
    out = capsys.readouterr().out
    assert "Days sealed: 1" in out, out
    # Вердикт обязан называть, чем именно проверено: оспорить сам набор —
    # законный ход стороны спора, и ей должно быть, что оспаривать.
    assert "root store version" in out and "freetsa" in out, out


def test_stamp_of_an_unknown_authority_is_unconfirmed_not_unsealed(sealed, capsys):
    """Служба, которой нет в наборе: «пломба стоит, но не подтверждена».

    Разница не косметическая. Штамп на месте и относится именно к этой
    суточной отметке — не сверена только подпись. Получатель, прочитавший «не
    запечатано», решит, что журнал не запечатан, и недооценит доказательство.

    Го и TypeScript подписи штампа не проверяют вовсе — для них это не редкий
    случай, а единственный достижимый исход на журнале с настоящим штампом.
    """
    empty = _store_without_freetsa(sealed)
    r = verify.verify_journal(sealed, {"trust_store": empty})
    assert r.ok, r.problems
    assert r.status == verify.UNVERIFIED, "пломба стоит: это не OPEN и не SEALED"
    assert [d["status"] for d in r.days] == [verify.UNVERIFIED]
    anchors = [a for d in r.days for a in d["anchors"]]
    assert len(anchors) == 1
    assert anchors[0]["status"] == "unverified" and anchors[0]["placed"]
    # Получателю мало «не подтверждена»: он обязан узнать, какой корень нужен.
    assert "fingerprint" in anchors[0]["detail"], anchors[0]["detail"]
    assert _fingerprint_of(CA)[:16] in anchors[0]["detail"], anchors[0]["detail"]

    from aihash import cli
    assert cli.main(["verify", sealed, "--trust-store", empty]) == 0
    out = capsys.readouterr().out
    assert "Days not sealed" not in out, \
        "верификатор объявил незапечатанным журнал с настоящим штампом:\n%s" % out
    assert "not confirmed here" in out, out
    assert "rfc3161" in out and "covers this checkpoint" in out, out
    assert "--tsa-ca" in out, "не сказано, чем достроить проверку:\n%s" % out

    for name, cmd in EXTERNAL:
        rc, text = _run(cmd, sealed)
        assert rc == 0, "%s отверг исправный журнал:\n%s" % (name, text)
        assert "Days not sealed" not in text, \
            "%s объявил незапечатанным журнал со штампом:\n%s" % (name, text)
        assert "not confirmed here" in text, \
            "%s не назвал состояние пломбы:\n%s" % (name, text)


def _store_without_freetsa(tmpdir_owner: str) -> str:
    """Набор корней, в котором нужного корня нет: так выглядит для получателя
    любая служба, до которой наш выпуск ещё не дошёл."""
    import json
    from aihash import trust as trust_mod
    data = json.load(open(trust_mod.ASSET, encoding="utf-8"))
    data["roots"] = [r for r in data["roots"] if r["id"] != "freetsa"]
    if not data["roots"]:
        # Пустой набор загрузка отвергает — кладём заведомо посторонний корень.
        data["roots"] = [_alien_root()]
    path = os.path.join(os.path.dirname(tmpdir_owner), "trust-without.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


def _alien_root() -> dict:
    """Самоподписанный корень, не имеющий отношения ни к одной службе штампов."""
    import tempfile
    from aihash import trust as trust_mod
    d = tempfile.mkdtemp(prefix="aihash-alien-")
    crt = os.path.join(d, "alien.crt")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", os.path.join(d, "alien.key"), "-out", crt,
                    "-days", "3650", "-subj", "/O=Nikto/CN=nikto.example"],
                   capture_output=True, timeout=120, check=True)
    pem = open(crt, "rb").read()
    der = trust_mod.pem_certs(pem)[0]
    return {"id": "alien", "name": "Посторонний корень", "pem": pem.decode(),
            "sha256": trust_mod.fingerprint(der), "subject": "", "source": "",
            "not_after": ""}


def test_journal_without_any_anchor_still_says_unsealed(sealed, capsys):
    """Обратная сторона: там, где пломбы действительно нет, смягчать нельзя.

    Без этой проверки предыдущую можно удовлетворить, просто убрав слова «не
    запечатано» отовсюду, — и продукт начнёт переоценивать себя.
    """
    os.rename(tsr_path(sealed), tsr_path(sealed) + ".aside")

    r = verify.verify_journal(sealed)
    assert r.ok and r.status == verify.OPEN, r.problems

    from aihash import cli
    assert cli.main(["verify", sealed]) == 0
    out = capsys.readouterr().out
    assert "Days not sealed" in out, out
    assert "not confirmed here" not in out, out

    for name, cmd in EXTERNAL:
        rc, text = _run(cmd, sealed)
        assert rc == 0 and "Days not sealed" in text, \
            "%s не сказал, что пломбы нет:\n%s" % (name, text)


# --- 2. контроль: подделка внутренне безупречна -----------------------------


def test_forgery_is_internally_flawless_without_the_stamp(sealed):
    """Без штампа подделка проходит проверку. Это и есть смысл теста: наши
    внутренние проверки её НЕ ловят, и ловить не могут — они пересчитаны."""
    forge(sealed)
    aside = tsr_path(sealed) + ".aside"
    os.rename(tsr_path(sealed), aside)

    r = verify.verify_journal(sealed, {"tsa_ca": CA})
    assert r.ok, ("подделка должна быть внутренне безупречной, иначе тест ниже "
                  "не отличает штамп от цепи: %s" % r.problems)
    assert r.records == META["records"]
    assert r.status == verify.OPEN, "без штампа журнал не может быть запечатан"

    for name, cmd in EXTERNAL:
        rc, out = _run(cmd, sealed)
        assert rc == 0, "%s нашёл изъян там, где его нет:\n%s" % (name, out)

    os.rename(aside, aside[: -len(".aside")])


# --- 3. отрицательный путь: штамп ловит то, что не поймал никто -------------


def test_forged_journal_is_caught_by_the_stamp_alone(sealed):
    """Решающая проверка. Если она вернёт OK, внешний якорь ничего не несёт и
    вся защита сводится к нашему же коду."""
    before = store.Layout(sealed).read_day(META["date"])["day_checkpoint"]
    after = forge(sealed)
    assert after != before, "порча не состоялась"
    assert os.path.exists(tsr_path(sealed)), "штамп обязан остаться на месте"

    r = verify.verify_journal(sealed, {"tsa_ca": CA})
    assert not r.ok, ("ПОДДЕЛКА ПРИНЯТА: внешний штамп не несёт ничего, "
                      "и вся защита сводится к нашему собственному коду")
    joined = " ".join(r.problems)
    assert "rfc3161" in joined, joined
    assert "not placed on this daily checkpoint" in joined, joined

    missed = []
    for name, cmd in EXTERNAL:
        rc, out = _run(cmd, sealed)
        if rc == 0:
            missed.append("%s ПРИНЯЛ подделку:\n%s" % (name, out))
    assert not missed, "\n".join(missed)


def test_forged_journal_is_caught_without_our_code_at_all(sealed):
    """Тот же вывод, полученный только openssl: наш код в этой проверке не
    участвует вообще."""
    if shutil.which("openssl") is None:
        pytest.skip("нужен openssl")
    after = forge(sealed)
    r = subprocess.run(["openssl", "ts", "-verify", "-digest", after,
                        "-in", tsr_path(sealed), "-CAfile", CA],
                       capture_output=True, timeout=60)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode != 0, out
    assert "Verification: FAILED" in out, out
    assert "imprint mismatch" in out, out


# --- 4. корень доверия не едет вместе с уликой ------------------------------
#
# Здесь противник сильнее, чем во всех предыдущих проверках. Он не подсовывает
# битый файл: он поднимает свой удостоверяющий центр, выписывает себе
# сертификат службы штампов и штампует им переписанный журнал. Полученный .tsr
# криптографически безупречен — `openssl ts -verify` принимает его без единого
# замечания, стоит дать ему корень этого центра.
#
# Единственное, чего противник не может, — попасть своим корнем в набор,
# который получатель взял отдельно от него.


needs_openssl = pytest.mark.skipif(not faketsa.available(), reason="нужен openssl")


@needs_openssl
def test_forged_stamp_with_its_own_root_in_the_bundle_is_not_accepted(
        sealed, tmp_path, capsys):
    """Требование целиком: поддельный штамп + поддельный корень в пакете.

    Проверка обязана НЕ пройти. Не «упасть с обвинением» — пройти она не имеет
    права, а обвинять здесь не за что: неизвестная служба и подделыватель для
    нас неразличимы, и rc=1 клеймил бы честный журнал, запечатанный службой,
    до которой наш выпуск не дошёл.
    """
    from aihash import bundle, cli

    forged_ckpt = forge(sealed)
    tsa = faketsa.FakeTSA(str(tmp_path / "tsa"))
    tsa.stamp(forged_ckpt, tsr_path(sealed))

    # Контроль: подделка внутренне безупречна и её собственный штамп настоящий.
    with open(tsr_path(sealed), "rb") as f:
        assert bytes.fromhex(forged_ckpt) in f.read(), "штамп не на ту отметку"
    ok = subprocess.run(["openssl", "ts", "-verify", "-digest", forged_ckpt,
                         "-in", tsr_path(sealed), "-CAfile", tsa.ca_cert],
                        capture_output=True, timeout=60)
    assert ok.returncode == 0, "поддельный штамп обязан быть настоящим RFC 3161"

    out = str(tmp_path / "forged.seal")
    bundle.build(sealed, META["stream_id"], [5], out, {"tsa_ca": tsa.ca_cert})
    with __import__("zipfile").ZipFile(out) as z:
        assert "certs/rfc3161-ca.pem" in z.namelist(), \
            "поддельный корень обязан лежать в пакете — иначе тест ничего не ловит"

    r = verify.verify_bundle(out)
    assert r["status"] != verify.SEALED, \
        "ПАКЕТ ЗАВЕРИЛ САМ СЕБЯ: корень из пакета создал доверие"
    assert cli.main(["verify", out]) != 0, "поддельный пакет вернул ноль"
    text = capsys.readouterr().out
    assert "not confirmed here" in text or "не подтверждена" in text, text

    # Тот же журнал проходит, если корень взять снаружи явным указанием. Это и
    # доказывает, что разница ровно в одном — откуда пришло доверие.
    assert verify.verify_bundle(out, {"tsa_ca": tsa.ca_cert})["status"] \
        == verify.SEALED, "контроль не сработал: тест доказывает не то"


@needs_openssl
def test_root_impersonating_a_known_authority_is_an_accusation(sealed, tmp_path):
    """Тонкий случай, который легко потерять при рефакторинге.

    Корень, назвавшийся именем известной службы, но с другим ключом, — это не
    «незнакомая служба», это выдача себя за чужую. Здесь обвинение честно, и
    только здесь.

    Остаточный риск: перевыпуск корня той же службой с тем же именем и НОВЫМ
    ключом отсюда выглядит так же. Перевыпуск с прежним ключом (продление
    срока) не обвиняется — он сравнивается по ключу, а не по отпечатку.
    """
    from aihash import anchors, store

    forged_ckpt = forge(sealed)
    known_subject = _subject_of(CA)
    tsa = faketsa.FakeTSA(str(tmp_path / "tsa"), root_subject=known_subject)
    tsa.stamp(forged_ckpt, tsr_path(sealed))

    day = store.Layout(sealed).read_day(META["date"])
    res = anchors.verify_file(tsr_path(sealed),
                              bytes.fromhex(day["day_checkpoint"]), {})
    assert res["status"] == anchors.FAILED, \
        "подмена известного корня осталась незамеченной: %s" % res["detail"]
    assert "freetsa" in res["detail"] and "different key" in res["detail"], \
        res["detail"]


def _subject_of(pem_path: str) -> str:
    """Имя корня в том виде, в каком его понимает openssl req -subj."""
    r = subprocess.run(["openssl", "x509", "-in", pem_path, "-noout",
                        "-subject", "-nameopt", "compat"],
                       capture_output=True, timeout=60, check=True)
    return r.stdout.decode("utf-8", "replace").split("subject=", 1)[1].strip()


# --- живой путь: настоящий запрос к службе, по требованию -------------------


LIVE = os.environ.get("AIHASH_LIVE_TSA") == "1"


@pytest.mark.skipif(not LIVE, reason="живой запрос к службе: AIHASH_LIVE_TSA=1")
def test_live_round_trip_against_the_authority(tmp_path):
    """Сквозной путь против живой службы: записать, запечатать, проверить,
    подделать, снова проверить.

    По умолчанию выключен: непрерывная сборка не должна зависеть от чужого
    сервиса, а фикстура выше даёт то же покрытие офлайн. Включать при смене
    кода работы со штампами и перед выпуском.
    """
    from aihash import seal

    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 86400_000
    j = journal.Journal(root, "romashka-prod", beacon_source=None,
                        clock=lambda: fixed)
    s = j.stream("voice-eu-3")
    for i in range(1, 11):
        s.record({"actor": "assistant", "output.text": "реплика %d" % i},
                 sync=True)
    j.close()

    layout = store.Layout(root)
    date = journal.period_of(fixed)
    seal.seal_day(layout, "romashka-prod", date)
    results = seal.anchor_day(layout, date, ["rfc3161"])
    if not results[0]["ok"]:
        pytest.skip("служба штампов недоступна: %s" % results[0].get("error"))

    r = verify.verify_journal(root, {"tsa_ca": CA})
    assert r.ok and r.status == verify.SEALED, r.problems

    META_LIVE = {"date": date, "stream_id": "voice-eu-3",
                 "realm_id": "romashka-prod", "records": 10}
    global META
    saved, META = META, META_LIVE
    try:
        forge(root)
    finally:
        META = saved

    r = verify.verify_journal(root, {"tsa_ca": CA})
    assert not r.ok, "живой штамп не поймал подделку"
    assert "not placed on this daily checkpoint" in " ".join(r.problems)
