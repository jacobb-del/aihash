"""Что уезжает в колесе на PyPI.

Написан после третьего подряд случая, когда игнор по каталогу проглатывал файл,
нужный не нам, а получателю: сначала `assets/`, потом `demo/`, потом снова
`assets/`. В последний раз это стоило бы главного обещания продукта — колесо
собиралось без `verify.html`, и пакет доказательства, собранный установленным
с PyPI aihash, приезжал к оппоненту без проверялки. Команда предупреждала, но
предупреждение читает тот, кто собирает, а страдает тот, кто проверяет.

Поэтому здесь проверяется СОДЕРЖИМОЕ КОЛЕСА ЦЕЛИКОМ, а не наличие отдельных
файлов: список ожидаемого задан явно, и любое расхождение в обе стороны —
отказ. Пропажа значит сломанное обещание; лишний файл значит, что в публикацию
уехало что-то незамеченным.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "..")
REPO = os.path.join(PKG, "..")

# Модули пакета. Список явный: добавление модуля — осознанное действие, и оно
# обязано быть видно в обзоре кода вместе с этой строкой.
MODULES = {
    "__init__.py", "anchors.py", "beacon.py", "bundle.py", "cli.py", "core.py",
    "journal.py", "otel.py", "report.py", "retention.py", "seal.py", "sinks.py",
    "store.py", "trust.py", "verify.py",
}

# Не-код, который обязан уехать вместе с кодом.
DATA = {
    "py.typed",
    # Верификатор, вкладываемый в каждый пакет доказательства. Без него
    # получатель обязан искать проверялку сам — а весь смысл в том, что не
    # обязан.
    "assets/verify.html",
    # Набор корней служб штампов: то, чем проверяется подпись. Без него
    # исправный журнал выглядит неподтверждённым.
    "assets/trust.json",
}


def _build_wheel(out_dir: str) -> str:
    """Собрать колесо без обращения в сеть.

    Изоляция сборки выключена намеренно: она тянет setuptools из интернета, а
    тест обязан работать и там, где сети нет.
    """
    r = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps",
         "--no-build-isolation", "-w", out_dir, PKG],
        capture_output=True, timeout=600)
    if r.returncode != 0:
        pytest.skip("колесо не собирается в этой среде: %s"
                    % r.stderr.decode("utf-8", "replace").strip()[-300:])
    wheels = [f for f in os.listdir(out_dir) if f.endswith(".whl")]
    assert len(wheels) == 1, wheels
    return os.path.join(out_dir, wheels[0])


@pytest.fixture(scope="module")
def wheel_names():
    tmp = tempfile.mkdtemp(prefix="aihash-wheel-")
    try:
        with zipfile.ZipFile(_build_wheel(tmp)) as z:
            yield set(z.namelist())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_wheel_carries_exactly_what_it_should(wheel_names):
    """Полный список содержимого, а не выборочные проверки."""
    inside = {n[len("aihash/"):] for n in wheel_names
              if n.startswith("aihash/") and not n.endswith("/")}
    expected = MODULES | DATA

    missing = expected - inside
    assert not missing, (
        "в колесе НЕТ файлов, без которых оно не выполняет обещанное: %s. "
        "Скорее всего их снова проглотил .gitignore или package-data."
        % sorted(missing))

    extra = inside - expected
    assert not extra, (
        "в колесо уехало незаявленное: %s. Если это осознанно — впишите в "
        "список выше, чтобы следующий человек увидел это в обзоре кода."
        % sorted(extra))


def test_packaged_data_is_not_swallowed_by_gitignore():
    """Самая нужная проверка из всех здешних.

    Колесо собирается из РАБОЧЕГО ДЕРЕВА, где файл лежит независимо от того,
    попадает ли он в репозиторий. Поэтому проверка содержимого колеса выше
    прошла бы и в тот раз, когда `verify.html` был проглочен игнором: у
    собирающего он есть, а у того, кто клонировал, — нет. Ровно так дефект и
    прожил незамеченным.

    Спрашивается не правило игнорирования, а факт: лежит ли файл в индексе.
    `git check-ignore` для этого не годится — он молчит про уже отслеживаемый
    файл, и проверка проходила бы вхолостую ровно там, где она нужна.
    """
    if not os.path.isdir(os.path.join(REPO, ".git")):
        pytest.skip("не репозиторий git — спрашивать не у кого")
    for rel in sorted(DATA):
        path = os.path.join("python", "aihash", rel)
        r = subprocess.run(["git", "ls-files", "--error-unmatch", path],
                           cwd=REPO, capture_output=True, timeout=60)
        assert r.returncode == 0, (
            "%s не отслеживается git: файл есть у вас и не будет у того, кто "
            "клонирует. Колесо, собранное из чистого клона, приедет без него — "
            "именно так уже трижды пропадали нужные файлы." % path)


def test_wheel_has_no_tests_and_no_junk(wheel_names):
    """Тесты, кеши и мусор системы в колесо не уезжают."""
    bad = [n for n in wheel_names
           if "/tests/" in n or n.startswith("tests/")
           or ".DS_Store" in n or "__pycache__" in n or n.endswith(".pyc")]
    assert not bad, bad


def test_embedded_verifier_matches_the_source_it_is_built_from():
    """Вшитая копия проверялки не должна расходиться с исходником.

    Копия коммитится ради колеса, и это цена: её можно забыть пересобрать
    после правки `verifier/src/`. Тогда получатель откроет страницу, которая
    ведёт себя не так, как остальные три реализации, — худший вид расхождения,
    потому что заметит его только он.
    """
    asset = os.path.join(PKG, "aihash", "assets", "verify.html")
    assert os.path.exists(asset), (
        "нет python/aihash/assets/verify.html — соберите: "
        "python3 verifier/build.py")

    build = os.path.join(REPO, "verifier", "build.py")
    if not os.path.exists(build):
        pytest.skip("нет verifier/build.py — сверять не с чем")

    with open(asset, "rb") as f:
        before = f.read()
    r = subprocess.run([sys.executable, build], capture_output=True, timeout=300)
    assert r.returncode == 0, r.stderr.decode("utf-8", "replace")[-300:]
    with open(asset, "rb") as f:
        after = f.read()
    assert before == after, (
        "python/aihash/assets/verify.html разошёлся с verifier/src/ — "
        "пересоберите и закоммитьте: python3 verifier/build.py")
