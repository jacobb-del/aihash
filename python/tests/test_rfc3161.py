"""Настоящий ответ службы штампов времени.

Фикстура получена живым прогоном против freetsa.org. До неё все тесты
использовали только пломбу feed, и разбор текстового вывода openssl вместо
сырых байтов DER заставлял верификатор ложно обвинять исправный штамп.
Ложное обвинение — худший отказ, какой этот продукт может выдать.
"""

import json
import os
import shutil

import pytest

from aihash import anchors

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "..", "..", "spec", "fixtures", "rfc3161")
META = json.load(open(os.path.join(FIX, "meta.json"), encoding="utf-8"))
TSR = os.path.join(FIX, META["file"])
CA = os.path.join(FIX, META["ca"])
TARGET = bytes.fromhex(META["target"])


def test_real_stamp_belongs_to_its_target():
    r = anchors.verify_file(TSR, TARGET, {})
    assert r["status"] != anchors.FAILED, \
        "исправный штамп объявлен несходящимся: %s" % r.get("detail")
    assert r["type"] == "rfc3161"
    assert META["tsa_time"] in (r.get("time") or "")


def test_wrong_target_is_rejected():
    r = anchors.verify_file(TSR, b"\x00" * 32, {})
    assert r["status"] == anchors.FAILED
    assert "not placed on this" in r["detail"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="нужен openssl")
def test_embedded_root_store_verifies_without_any_configuration():
    """Одна команда: корень берётся из вшитого набора, а не от получателя."""
    r = anchors.verify_file(TSR, TARGET, {})
    assert r["status"] == anchors.OK, r["detail"]
    assert r["root"]["id"] == "freetsa"
    assert "root store version" in r["detail"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="нужен openssl")
def test_authority_outside_the_store_is_not_claimed_verified(tmp_path):
    """Пломба, которую нечем подтвердить, обязана называться непроверенной, а
    не «в порядке», — и обязана сказать, какой корень нужен."""
    r = anchors.verify_file(TSR, TARGET,
                            {"trust_store": _store_without_freetsa(tmp_path)})
    assert r["status"] == anchors.UNVERIFIED
    assert r["placed"], "пломба стоит — это не «пломбы нет»"
    assert "not in the root store" in r["detail"]
    assert "fingerprint" in r["detail"] and "--tsa-ca" in r["detail"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="нужен openssl")
def test_signature_verifies_with_an_explicitly_given_certificate():
    """Переопределение главнее набора: службу, которой в наборе нет, обязано
    быть можно проверить, не дожидаясь нашего выпуска."""
    r = anchors.verify_file(TSR, TARGET, {"tsa_ca": CA})
    assert r["status"] == anchors.OK, r["detail"]
    assert "--tsa-ca override" in r["detail"]


@pytest.mark.skipif(shutil.which("openssl") is None, reason="нужен openssl")
def test_chain_that_does_not_build_is_unconfirmed_not_an_accusation():
    """Цепь не собралась — это НЕ обвинение.

    Отличить «не та служба» от «плохая подпись» можно было бы только разбором
    текста ошибок openssl, а этот приём в проекте уже приводил к ложному
    обвинению. Добросовестный пользователь неизвестной нам службы и
    подделыватель отсюда неразличимы, и клеймить обоих дороже, чем пропустить:
    подделку поймает суд, а компания, которой инструмент солгал на честной
    записи, его больше не запустит.

    Обвинять умеет ровно одна проверка — принадлежность штампа отметке, где мы
    читаем сырые байты сами (test_wrong_target_is_rejected выше).
    """
    r = anchors.verify_file(TSR, TARGET, {"tsa_ca": os.path.join(FIX, "meta.json")})
    assert r["status"] != anchors.OK, "мусор вместо корня не смеет давать «ОК»"
    assert r["status"] == anchors.UNVERIFIED
    assert r["placed"]


def _store_without_freetsa(tmp_path) -> str:
    import json
    from aihash import trust
    data = json.load(open(trust.ASSET, encoding="utf-8"))
    # Заменяем корень на посторонний: пустой набор загрузка отвергает, и это
    # правильно — набор без корней и отсутствие набора это разные вещи.
    data["roots"] = [dict(data["roots"][0])]
    data["roots"][0]["id"] = "alien"
    data["roots"][0]["pem"] = _self_signed(tmp_path)
    ders = trust.pem_certs(data["roots"][0]["pem"].encode())
    data["roots"][0]["sha256"] = trust.fingerprint(ders[0])
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _self_signed(tmp_path) -> str:
    import subprocess
    crt = tmp_path / "alien.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(tmp_path / "alien.key"), "-out", str(crt),
                    "-days", "3650", "-subj", "/O=Nikto/CN=nikto.example"],
                   capture_output=True, timeout=120, check=True)
    return crt.read_text(encoding="ascii")
