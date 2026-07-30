"""Три реализации проверки обязаны давать один вердикт.

Python, JavaScript и Go написаны независимо. Разъезжаются такие вещи молча, и
этот тест — единственное, что ловит расхождение до того, как оно попадёт в
спор.

Каждая реализация пропускается отдельно, если её инструмент не установлен:
это не повод считать проект сломанным на чужой машине, но и не повод считать
совместимость проверенной.
"""

import json
import os
import shutil
import subprocess
import zipfile

import pytest

import aihash
from aihash import bundle, journal, seal, store, verify

REALM = "romashka-prod"
STREAM = "voice-eu-3"
HERE = os.path.dirname(os.path.abspath(__file__))
JS = os.path.join(HERE, "..", "..", "verifier", "dist", "aihash-verify.js")
GO = os.path.join(HERE, "..", "..", "verifier", "dist", "aihash-verify")

def _runnable(cmd) -> bool:
    """Запускается ли реализация ЗДЕСЬ: файл может быть собран под другую
    систему или архитектуру, и тогда тест падает «Exec format error» вместо
    пропуска. Поймано кросс-машинным прогоном."""
    try:
        subprocess.run(list(cmd) + ["--version"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


has_node = (shutil.which("node") is not None and os.path.exists(JS)
            and _runnable(["node", JS]))
has_go = (os.path.exists(GO) and os.access(GO, os.X_OK) and _runnable([GO]))

needs_node = pytest.mark.skipif(
    not has_node, reason="нужен node и python3 verifier/build.py")
needs_go = pytest.mark.skipif(
    not has_go, reason="нужен собранный бинарь: sh verifier/go/build.sh")


def run_js(path):
    r = subprocess.run(["node", JS, path], capture_output=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def run_go(path):
    r = subprocess.run([GO, path], capture_output=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def write_journal(tmp_path):
    root = str(tmp_path / "journal")
    fixed = journal.now_ms() - 86400_000
    log = aihash.BoundStream(
        journal.Journal(root, REALM, beacon_source=None, clock=lambda: fixed), STREAM)
    for f in [{"actor": "customer", "customer.name": "Пётр Ильич Сергеев",
               "input.text": "Когда придёт возврат?"},
              {"actor": "assistant", "tool.name": "orders.get",
               "tool.result": '{"status":"cancelled"}'},
              {"actor": "assistant", "output.text": "возврат придёт в течение 5 дней",
               "config.model": "gpt-4o-2026-02-11"},
              {"actor": "system", "billing.op": "RF-88214"}]:
        log.record(f, sync=True)
    log.close()
    layout = store.Layout(root)
    date = journal.period_of(fixed)
    seal.seal_day(layout, REALM, date)
    seal.anchor_day(layout, date, ["feed"])
    return root, date


@pytest.fixture()
def sealed(tmp_path):
    root, _ = write_journal(tmp_path)
    out = str(tmp_path / "ep.seal")
    bundle.build(root, STREAM, [3], out)
    return out


def repack(src, dst, patch):
    with zipfile.ZipFile(src) as zin, \
            zipfile.ZipFile(dst, "w", zipfile.ZIP_STORED) as zout:
        for name in zin.namelist():
            zout.writestr(name, patch(name, zin.read(name)))
    return dst


# --- исправный пакет: все три принимают ------------------------------------


def test_python_accepts(sealed):
    r = verify.verify_bundle(sealed)
    assert r["status"] == verify.SEALED, r["problems"]


@needs_node
def test_js_accepts(sealed):
    rc, text = run_js(sealed)
    assert rc == 0, text
    assert "сходится и запечатано" in text


@needs_go
def test_go_accepts(sealed):
    rc, text = run_go(sealed)
    assert rc == 0, text
    assert "суточная отметка запечатана" in text


@needs_go
def test_go_verifies_whole_journal(tmp_path):
    root, _ = write_journal(tmp_path)
    rc, text = run_go(root)
    assert rc == 0, text
    assert "Цепь сходится на всём протяжении" in text
    assert "Запечатано суток: 1" in text


# --- подделка: все три отвергают одинаково ---------------------------------


@pytest.fixture()
def tampered(sealed, tmp_path):
    return repack(sealed, str(tmp_path / "edited.seal"),
                  lambda n, d: d.replace("5 дней".encode(), "5 раб.дн".encode())
                  if n == "records.jsonl" else d)


def test_python_rejects_tamper(tampered):
    r = verify.verify_bundle(tampered)
    assert r["status"] == verify.BROKEN
    assert any("seq=3" in p for p in r["problems"])


@needs_node
def test_js_rejects_tamper(tampered):
    rc, text = run_js(tampered)
    assert rc == 1, text
    assert "seq=3" in text


@needs_go
def test_go_rejects_tamper(tampered):
    rc, text = run_go(tampered)
    assert rc == 1, text
    assert "seq=3" in text


@pytest.fixture()
def broken_feed(sealed, tmp_path):
    def patch(name, data):
        if name != "anchors/feed.jsonl":
            return data
        e = json.loads(data.decode("utf-8").strip())
        e["target"] = "00" * 32
        return (json.dumps(e) + "\n").encode("utf-8")
    return repack(sealed, str(tmp_path / "feed.seal"), patch)


def test_all_reject_broken_feed(broken_feed):
    assert verify.verify_bundle(broken_feed)["status"] == verify.BROKEN
    if has_node:
        assert run_js(broken_feed)[0] == 1
    if has_go:
        assert run_go(broken_feed)[0] == 1


@needs_go
def test_go_catches_deleted_record_in_journal(tmp_path):
    root, _ = write_journal(tmp_path)
    date = journal.period_of(journal.now_ms() - 86400_000)
    path = store.Layout(root).segment_file(STREAM, date)
    lines = open(path, encoding="utf-8").read().splitlines()
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines[:1] + lines[2:]) + "\n")
    rc, text = run_go(root)
    assert rc == 1, text
    assert "пропуск в цепи" in text


# --- содержимое пакета -----------------------------------------------------


def test_bundle_carries_its_own_verifier(sealed):
    with zipfile.ZipFile(sealed) as z:
        names = set(z.namelist())
        assert "verify.html" in names
        page = z.read("verify.html").decode("utf-8")
        txt = z.read("VERIFY.txt").decode("utf-8")
    assert "http://" not in page and "https://" not in page, \
        "страница обязана быть самодостаточной"
    assert "<script src=" not in page
    assert "не является" in page and "независимой" in page, \
        "страница обязана предупреждать, что верификатор от оппонента не независим"
    assert "не независимая проверка" in " ".join(txt.split())
