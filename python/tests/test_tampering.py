"""Проверка обязана ПРОВАЛИВАТЬСЯ. Самый важный набор в проекте.

Если verify говорит «сходится» там, где не должен, продукт не работает — и мы
об этом не узнаем. Всё остальное в кодовой базе имеет смысл только при условии,
что этот файл зелёный.

Устройство каждого теста:

  1. Собрать журнал из 10 записей, закрыть сутки, поставить пломбу.
  2. Убедиться, что НЕИЗМЕНЁННЫЙ журнал принимается. Без этой проверки тест
     может проходить впустую: сломанная заготовка отвергается всегда.
  3. Убедиться, что порча действительно произошла — иначе «отвергнуто» ничего
     не доказывает.
  4. Проверить журнал ВСЕМИ доступными реализациями и потребовать отказа от
     каждой. Подделка, которую ловят три верификатора из четырёх, — это
     молчаливое расхождение, а оно опаснее прямой ошибки.

Порча делается инструментами самой библиотеки там, где это нужно: противник с
исходным кодом ровно так и поступит, и слабая подделка ничего не проверяет.
"""

import json
import os
import shutil
import subprocess

import pytest

from aihash import core, journal, seal, store, verify

REALM = "romashka-prod"
STREAM = "voice-eu-3"
N = 10

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
GO = os.path.join(REPO, "verifier", "dist", "aihash-verify")
JS = os.path.join(REPO, "verifier", "dist", "aihash-verify.js")
TS = os.path.join(REPO, "typescript", "dist", "src", "cli.js")
FIXTURE = os.path.join(REPO, "spec", "fixtures", "rfc3161")


# --- запуск чужих реализаций ------------------------------------------------


def runnable(cmd) -> bool:
    """Запускается ли эта реализация ЗДЕСЬ.

    Проверять наличие файла и бит запуска недостаточно: в verifier/dist может
    лежать бинарь, собранный под другую систему или другую архитектуру, — и
    тогда тест падает с «Exec format error» вместо того, чтобы честно
    пропуститься. Поймано кросс-машинным прогоном: бинарь для macOS/arm64,
    попавший в контейнер linux/amd64, ронял четыре теста подряд.
    """
    try:
        subprocess.run(list(cmd) + ["--version"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _external(journals: bool):
    """Реализации, доступные на этой машине.

    Верификатор на JavaScript работает только с пакетом: разбор каталога в
    общее ядро не входит, иначе verify.html перестал бы быть файлом, который
    можно прочитать целиком.
    """
    out = []
    if os.path.exists(GO) and os.access(GO, os.X_OK) and runnable([GO]):
        out.append(("Go", [GO]))
    node = shutil.which("node")
    if node and os.path.exists(TS) and runnable([node, TS]):
        out.append(("TypeScript", [node, TS, "verify"]))
    if node and os.path.exists(JS) and not journals and runnable([node, JS]):
        out.append(("JavaScript", [node, JS]))
    return out


EXTERNAL = _external(journals=True)
EXTERNAL_BUNDLE = _external(journals=False)


def _run(cmd, path):
    r = subprocess.run(cmd + [path], capture_output=True, timeout=120)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def assert_all_accept(root):
    """Неизменённый журнал обязаны принять все."""
    r = verify.verify_journal(root)
    assert r.ok, "Python отверг исправный журнал: %s" % r.problems
    assert r.status == verify.SEALED, "исправный журнал не считается запечатанным"
    for name, cmd in EXTERNAL:
        rc, out = _run(cmd, root)
        assert rc == 0, "%s отверг исправный журнал (rc=%d):\n%s" % (name, rc, out)


def assert_all_reject(root, expect=None):
    """Испорченный журнал обязаны отвергнуть все до единой."""
    r = verify.verify_journal(root)
    assert not r.ok, "Python ПРИНЯЛ подделанный журнал — продукт не работает"
    joined = " ".join(r.problems)
    if expect:
        assert expect in joined, "Python отверг, но не по той причине: %s" % joined

    missed = []
    for name, cmd in EXTERNAL:
        rc, out = _run(cmd, root)
        if rc == 0:
            missed.append("%s ПРИНЯЛ подделку (rc=0):\n%s" % (name, out))
    assert not missed, "\n".join(missed)


# --- заготовка --------------------------------------------------------------


@pytest.fixture()
def sealed(tmp_path):
    """Журнал из 10 записей за вчера: закрыт и запечатан."""
    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 86400_000
    j = journal.Journal(root, REALM, beacon_source=None, clock=lambda: fixed)
    s = j.stream(STREAM)
    for i in range(1, N + 1):
        s.record({"actor": "assistant" if i % 2 else "customer",
                  "output.text": "реплика номер %d" % i,
                  "turn": str(i)}, sync=True)
    j.close()

    layout = store.Layout(root)
    date = journal.period_of(fixed)
    seal.seal_day(layout, REALM, date)
    seal.anchor_day(layout, date, ["feed"])
    assert len(layout.read_segment(STREAM, date)) == N
    return root, date


def seg_path(root, date):
    return store.Layout(root).segment_file(STREAM, date)


def load_records(root, date):
    return store.Layout(root).read_segment(STREAM, date)


def save_records(root, date, recs):
    with open(seg_path(root, date), "w", encoding="utf-8") as f:
        for rec in recs:
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")


def field_of(rec, name):
    return next(f for f in rec["fields"] if f["name"] == name)


# --- контроль: неизменённый журнал принимается ------------------------------


def test_00_untouched_journal_is_accepted(sealed):
    """Если этот тест падает, все остальные ничего не значат: они могли бы
    проходить просто потому, что заготовка сломана изначально."""
    root, date = sealed
    assert_all_accept(root)
    assert verify.verify_journal(root).records == N


def test_00_all_four_implementations_are_actually_running():
    """Набор теряет смысл, если чужие реализации молча не запускаются."""
    assert EXTERNAL, ("ни одна внешняя реализация не найдена — соберите: "
                      "sh verifier/go/build.sh, python3 verifier/build.py, "
                      "npx tsc в typescript/")
    assert len(EXTERNAL) == 2, \
        "журнал проверяют не все: %s" % [n for n, _ in EXTERNAL]
    assert len(EXTERNAL_BUNDLE) == 3, \
        "пакет проверяют не все: %s" % [n for n, _ in EXTERNAL_BUNDLE]


# --- 1. изменён один символ в записи №5 -------------------------------------


def test_01_single_character_changed_in_record_5(sealed):
    root, date = sealed
    assert_all_accept(root)

    recs = load_records(root, date)
    before = field_of(recs[4], "output.text")["s"]
    field_of(recs[4], "output.text")["s"] = before.replace("5", "6")
    assert field_of(recs[4], "output.text")["s"] != before, "порча не состоялась"
    save_records(root, date, recs)

    assert_all_reject(root, "seq=5")


# --- 2. запись №5 удалена целиком -------------------------------------------


def test_02_record_5_deleted_entirely(sealed):
    root, date = sealed
    assert_all_accept(root)

    recs = load_records(root, date)
    del recs[4]
    save_records(root, date, recs)
    assert len(load_records(root, date)) == N - 1, "порча не состоялась"

    assert_all_reject(root, "gap")


# --- 3. запись дописана после постановки пломбы -----------------------------


def test_03_record_appended_after_sealing(sealed):
    """Слабая подделка — просто дописать строку — ловится звеном. Здесь
    дописывается ПРАВИЛЬНО СЦЕПЛЕННАЯ запись: её обязана поймать отметка
    отрезка, потому что count и last_seq в ней уже запечатаны."""
    root, date = sealed
    assert_all_accept(root)

    recs = load_records(root, date)
    prev = bytes.fromhex(recs[-1]["link"])
    salt = core.new_salt()
    fields = [store.encode_field("actor", salt, "assistant")]
    croot = core.content_root([{"name": "actor", "salt": salt,
                               "value": b"assistant"}])
    ts = recs[-1]["ts"] + 1000
    link = core.link(prev, N + 1, croot, ts)
    with open(seg_path(root, date), "a", encoding="utf-8") as f:
        f.write(store.record_line(N + 1, ts, fields, croot, link) + "\n")

    added = load_records(root, date)
    assert len(added) == N + 1 and added[-1]["seq"] == N + 1, "порча не состоялась"
    # Звено дописанной записи корректно — ловить её обязана именно отметка.
    assert core.link(bytes.fromhex(added[-2]["link"]), N + 1,
                     bytes.fromhex(added[-1]["content_root"]),
                     added[-1]["ts"]).hex() == added[-1]["link"]

    assert_all_reject(root)


# --- 4. записи №3 и №7 переставлены местами ---------------------------------


def test_04_records_3_and_7_swapped(sealed):
    root, date = sealed
    assert_all_accept(root)

    recs = load_records(root, date)
    third, seventh = recs[2]["fields"], recs[6]["fields"]
    recs[2]["fields"], recs[6]["fields"] = seventh, third
    recs[2]["content_root"], recs[6]["content_root"] = \
        recs[6]["content_root"], recs[2]["content_root"]
    save_records(root, date, recs)

    after = load_records(root, date)
    assert field_of(after[2], "turn")["s"] == "7", "порча не состоялась"
    assert field_of(after[6], "turn")["s"] == "3"

    assert_all_reject(root, "seq=3")


# --- 5. цепь пересчитана заново с изменённым содержимым ---------------------


def test_05_whole_chain_recomputed_with_new_content(sealed):
    """Самая сильная подделка: противник переписывает содержимое И пересчитывает
    всё внутри журнала — отпечатки записей, звенья, корень отрезка, отметку
    отрезка и суточную отметку. Внутренне такой журнал безупречен.

    Поймать его обязана пломба: суточная отметка опубликована вовне, и новая с
    ней не совпадёт. Этот тест доказывает, что пломба несущая, а не украшение.
    """
    root, date = sealed
    assert_all_accept(root)
    layout = store.Layout(root)
    original_day = layout.read_day(date)["day_checkpoint"]

    recs = load_records(root, date)
    prev = core.genesis(STREAM)
    links = []
    for rec in recs:
        if rec["seq"] == 5:
            salt = core.new_salt()
            f = field_of(rec, "output.text")
            f["salt"], f["s"] = salt.hex(), "реплика номер 5, переписанная"
        calc = store.fields_for_root(rec["fields"])
        croot = core.content_root(calc)
        rec["content_root"] = croot.hex()
        prev = core.link(prev, rec["seq"], croot, rec["ts"])
        rec["link"] = prev.hex()
        links.append(prev)
    save_records(root, date, recs)

    # Пересчитываем отметку отрезка так, будто ничего не произошло.
    root_hash = core.seg_root(links)
    ck = core.seg_ckpt(STREAM, date, 1, N, N, core.genesis(STREAM), links[-1],
                       root_hash, core.ZERO32)
    store.write_json(layout.segment_ckpt_file(STREAM, date), {
        "format": core.FORMAT_VERSION, "stream_id": STREAM, "period_id": date,
        "first_seq": 1, "last_seq": N, "count": N,
        "link_before": core.genesis(STREAM).hex(), "link_last": links[-1].hex(),
        "segment_root": root_hash.hex(), "prev_checkpoint": core.ZERO32.hex(),
        "checkpoint": ck.hex()})

    # И суточную отметку тоже.
    day_root = core.day_root([ck])
    day_ck = core.day_ckpt(REALM, date, 1, day_root, core.ZERO32)
    store.write_json(layout.day_file(date), {
        "format": core.FORMAT_VERSION, "realm_id": REALM, "date": date,
        "streams": [STREAM], "segment_checkpoints": [ck.hex()],
        "day_root": day_root.hex(), "prev_checkpoint": core.ZERO32.hex(),
        "day_checkpoint": day_ck.hex()})

    assert day_ck.hex() != original_day, "порча не состоялась"
    assert "переписанная" in open(seg_path(root, date), encoding="utf-8").read()

    # Всё внутри журнала пересчитано и согласовано: цепь, отметки, дерево.
    # Единственное, чего противник переписать не может, — опубликованная пломба.
    assert_all_reject(root, "seal")


# --- 6. файл пломбы удалён: «не подтверждено», а НЕ «ОК» --------------------


def test_06_anchor_file_removed_is_not_proven_not_ok(sealed):
    """Пропажа пломбы — не подделка, но и не «всё в порядке». Между этими
    двумя ответами и лежит весь смысл продукта."""
    root, date = sealed
    assert_all_accept(root)
    layout = store.Layout(root)

    os.remove(os.path.join(layout.anchors_dir(), "feed.jsonl"))
    assert not os.path.exists(os.path.join(layout.anchors_dir(), "feed.jsonl"))

    r = verify.verify_journal(root)
    assert r.ok, "пропажа пломбы объявлена подделкой: %s" % r.problems
    assert r.status != verify.SEALED, "журнал без пломбы объявлен запечатанным"
    assert r.status == verify.OPEN
    assert date in [d["date"] for d in r.days if d["status"] == verify.OPEN]

    for name, cmd in EXTERNAL:
        rc, out = _run(cmd, root)
        assert "Days sealed" not in out, \
            "%s объявил запечатанным журнал без пломбы:\n%s" % (name, out)
        assert "Days not sealed" in out, \
            "%s не сказал, что пломбы нет:\n%s" % (name, out)


def test_06b_bundle_without_anchor_does_not_exit_zero(sealed, tmp_path):
    """У пакета отдельный код возврата: ноль означал бы «доказано» там, где не
    доказано ничего, а автоматическая проверка смотрит именно на него."""
    from aihash import bundle, cli
    root, date = sealed
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [5], out)
    assert cli.main(["verify", out]) == 0, "исправный пакет обязан давать ноль"
    for name, cmd in EXTERNAL_BUNDLE:
        rc, _ = _run(cmd, out)
        assert rc == 0, "%s отверг исправный пакет" % name

    os.remove(os.path.join(store.Layout(root).anchors_dir(), "feed.jsonl"))
    bare = str(tmp_path / "bare.seal")
    bundle.build(root, STREAM, [5], bare)

    assert verify.verify_bundle(bare)["status"] == verify.OPEN
    assert cli.main(["verify", bare]) == 3, "пакет без пломбы вернул «ОК»"
    for name, cmd in EXTERNAL:
        rc, text = _run(cmd, bare)
        assert rc != 0, "%s вернул ноль на пакете без пломбы:\n%s" % (name, text)
        assert "is not proven" in text, "%s не сказал этого словами:\n%s" % (name, text)


# --- 7. подставлена пломба от другого дня -----------------------------------


def test_07_anchor_from_another_day(sealed):
    """Штамп настоящий, служба настоящая, подпись сойдётся — но заверяет он
    чужую суточную отметку."""
    root, date = sealed
    assert_all_accept(root)
    layout = store.Layout(root)

    meta = json.load(open(os.path.join(FIXTURE, "meta.json"), encoding="utf-8"))
    assert meta["target"] != layout.read_day(date)["day_checkpoint"]
    shutil.copy(os.path.join(FIXTURE, meta["file"]),
                layout.anchor_file(date, "rfc3161", "tsr"))

    assert_all_reject(root, "not placed on this")


def test_07b_feed_publishes_a_different_mark_for_this_day(sealed):
    """Лента цела и внутренне согласована, но за ЭТИ сутки в ней опубликована
    другая отметка. Это не «пломбы нет» — это прямое противоречие между
    журналом и опубликованным, и оно обязано быть отказом.

    Ровно этот случай и есть смысл ленты: без него противник, пересчитавший
    журнал целиком, прошёл бы проверку."""
    root, date = sealed
    assert_all_accept(root)
    layout = store.Layout(root)

    feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
    original = json.loads(open(feed, encoding="utf-8").read().strip())
    other = "aa" * 32
    rebuilt = core.H(b"aihash/feed/1", core.lp(date.encode()),
                     bytes.fromhex(other), core.ZERO32)
    with open(feed, "w", encoding="utf-8") as f:
        f.write(json.dumps({"seq": 1, "date": date, "target": other,
                            "prev": core.ZERO32.hex(),
                            "entry": rebuilt.hex()}) + "\n")
    assert json.loads(open(feed, encoding="utf-8").read())["target"] \
        != original["target"], "порча не состоялась"

    assert_all_reject(root, "DIFFERENT checkpoint")


def test_07c_two_marks_for_one_day_is_forking(sealed):
    """Две разные суточные отметки за одну дату — раздвоение журнала. Ради
    обнаружения именно этого лента и публикуется вовне."""
    root, date = sealed
    assert_all_accept(root)
    layout = store.Layout(root)

    feed = os.path.join(layout.anchors_dir(), "feed.jsonl")
    first = json.loads(open(feed, encoding="utf-8").read().strip())
    other = "bb" * 32
    prev = bytes.fromhex(first["entry"])
    entry = core.H(b"aihash/feed/1", core.lp(date.encode()),
                   bytes.fromhex(other), prev)
    with open(feed, "a", encoding="utf-8") as f:
        f.write(json.dumps({"seq": 2, "date": date, "target": other,
                            "prev": prev.hex(), "entry": entry.hex()}) + "\n")

    assert_all_reject(root, "forked")


# --- 8. изменена только временная метка -------------------------------------


def test_08_only_the_timestamp_changed(sealed):
    """Время выглядит как безобидная метаданная, но оно связано звеном.
    Сдвиг на секунду — уже другая цепь."""
    root, date = sealed
    assert_all_accept(root)

    recs = load_records(root, date)
    before = recs[4]["ts"]
    recs[4]["ts"] = before + 1000
    save_records(root, date, recs)
    assert load_records(root, date)[4]["ts"] != before, "порча не состоялась"

    assert_all_reject(root, "seq=5")


# --- дополнительно: подделка внутри пакета доказательства -------------------


@pytest.mark.parametrize("target,expect", [
    ("records.jsonl", "seq=5"),
    ("segment.json", "path to the segment root"),
    ("day.json", "path to the daily root"),
])
def test_09_bundle_tampering_is_caught(sealed, tmp_path, target, expect):
    """Пакет — это то, что реально попадает к оппоненту."""
    import zipfile
    from aihash import bundle
    root, date = sealed
    good = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [5], good)
    assert verify.verify_bundle(good)["status"] == verify.SEALED

    bad = str(tmp_path / "bad.seal")
    with zipfile.ZipFile(good) as zin, \
            zipfile.ZipFile(bad, "w", zipfile.ZIP_STORED) as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name == target:
                obj = data.decode("utf-8")
                if target == "records.jsonl":
                    obj = obj.replace("реплика номер 5", "реплика номер 6")
                elif target == "segment.json":
                    d = json.loads(obj)
                    d["segment_root"] = "bb" * 32
                    obj = json.dumps(d)
                else:
                    d = json.loads(obj)
                    d["day_root"] = "cc" * 32
                    obj = json.dumps(d)
                data = obj.encode("utf-8")
            zout.writestr(name, data)

    r = verify.verify_bundle(bad)
    assert r["status"] == verify.BROKEN, "подделка в %s не поймана" % target
    assert expect in " ".join(r["problems"]), r["problems"]

    for name, cmd in EXTERNAL_BUNDLE:
        rc, out = _run(cmd, bad)
        assert rc == 1, "%s принял подделанный пакет (%s):\n%s" % (name, target, out)
