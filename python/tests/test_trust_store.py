"""Набор корней: происхождение, целостность, и то, что он вообще решает.

Корень доверия — единственное во всей проверке, что берётся не из пакета. Если
его можно подменить правкой файла или подсунуть вместе с уликой, проверка
подписи превращается в церемонию.
"""

import json
import os

import pytest

from aihash import trust

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..")
SPEC_TRUST = os.path.join(REPO, "spec", "trust")


def test_embedded_store_loads_and_recomputes_fingerprints():
    """Загрузка пересчитывает отпечаток каждого корня, а не верит записанному."""
    store = trust.load()
    assert len(store) >= 1
    assert store.version >= 1
    for root in store.roots:
        ders = trust.pem_certs(root.pem)
        assert len(ders) == 1
        assert trust.fingerprint(ders[0]) == root.sha256


def test_tampered_root_is_rejected_not_used(tmp_path):
    """Подменённый корень обязан ронять загрузку.

    Молча взять корень, отпечаток которого не сошёлся, — худшее из возможного:
    получатель увидит «подпись проверена» и не узнает, чем именно.
    """
    data = json.loads(open(trust.ASSET, encoding="utf-8").read())
    data["roots"][0]["sha256"] = "00" * 32
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(trust.TrustError) as e:
        trust.load(str(path))
    assert "tampered with" in str(e.value)
    assert trust.store_for({"trust_store": str(path)}) is None


def test_every_root_states_where_it_came_from():
    """Вшитый корень без происхождения — это «доверяйте нам, потому что мы так
    сказали». Манифест обязан отвечать: откуда взят, когда, чем подтверждён."""
    manifest = json.load(open(os.path.join(SPEC_TRUST, "roots.json"),
                              encoding="utf-8"))
    assert manifest["format"] == trust.FORMAT
    assert isinstance(manifest["version"], int)
    assert manifest.get("policy"), "набор обязан объявлять критерий попадания в него"
    for entry in manifest["roots"]:
        for key in ("id", "name", "sha256", "source", "obtained", "obtained_how"):
            assert entry.get(key), "у корня %s нет поля %s" % (entry.get("id"), key)
        assert entry["source"].startswith("https://"), entry["id"]


def test_embedded_copy_matches_the_source_of_truth():
    """Вшитая копия не должна расходиться со spec/trust.

    Расхождение означает, что кто-то правил копию, а не источник, — и следующая
    пересборка молча вернёт всё назад.
    """
    spec_manifest = json.load(open(os.path.join(SPEC_TRUST, "roots.json"),
                                   encoding="utf-8"))
    embedded = trust.load()
    assert embedded.version == spec_manifest["version"]
    by_id = {r.id: r for r in embedded.roots}
    assert set(by_id) == {e["id"] for e in spec_manifest["roots"]}
    for entry in spec_manifest["roots"]:
        pem = open(os.path.join(SPEC_TRUST, entry["file"]), "rb").read()
        assert by_id[entry["id"]].pem == pem, (
            "корень %s в spec/trust и в python/aihash/assets/trust.json "
            "различаются — пересоберите: python3 spec/tools/buildtrust.py"
            % entry["id"])
        assert by_id[entry["id"]].sha256 == entry["sha256"]
