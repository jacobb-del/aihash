"""Пломбы: постановка и офлайн-проверка.

Три типа, три разные аудитории, некоррелированные отказы:

  rfc3161        — суд и страховщик; при квалификации по eIDAS имеет
                   установленную законом презумпцию
  opentimestamps — технический скептик; никто не контролирует
  feed           — обнаружение раздвоения журнала

Проверка каждого типа обязана работать без обращения к нашим серверам.
Там, где офлайн-проверка невозможна без стороннего материала (сертификат
службы штампов, узел Bitcoin), статус честно возвращается как «не проверено»,
а не как «в порядке».
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from typing import Optional

from . import core, store
from . import trust as trust_mod

DEFAULT_TSA = "https://freetsa.org/tsr"

OK = "ok"
UNVERIFIED = "unverified"
FAILED = "failed"


# --- минимальный DER --------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _tlv(0x02, b)


def _timestamp_req(digest: bytes, nonce: int) -> bytes:
    sha256_oid = _tlv(0x06, bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]))
    algid = _tlv(0x30, sha256_oid + _tlv(0x05, b""))
    imprint = _tlv(0x30, algid + _tlv(0x04, digest))
    cert_req = _tlv(0x01, b"\xff")
    return _tlv(0x30, _der_int(1) + imprint + _der_int(nonce) + cert_req)


# --- постановка -------------------------------------------------------------


def stamp(kind: str, target: bytes, layout: store.Layout, date: str,
          config: dict) -> dict:
    fn = _STAMPERS.get(kind)
    if fn is None:
        raise core.FormatError("неизвестный тип пломбы: %s" % kind)
    return fn(target, layout, date, config)


def _stamp_rfc3161(target: bytes, layout: store.Layout, date: str,
                   config: dict) -> dict:
    url = config.get("tsa_url", DEFAULT_TSA)
    nonce = int.from_bytes(os.urandom(8), "big")
    req = urllib.request.Request(
        url, data=_timestamp_req(target, nonce),
        headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=config.get("timeout", 15.0)) as r:
        body = r.read()
    if not body:
        raise RuntimeError("служба штампов вернула пустой ответ")
    path = layout.anchor_file(date, "rfc3161", "tsr")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    return {"path": path, "tsa_url": url}


def _stamp_ots(target: bytes, layout: store.Layout, date: str,
               config: dict) -> dict:
    exe = shutil.which("ots")
    if exe is None:
        raise RuntimeError(
            "клиент opentimestamps не установлен (pip install opentimestamps-client)")
    tmp = layout.anchor_file(date, "opentimestamps", "bin")
    os.makedirs(os.path.dirname(tmp), exist_ok=True)
    with open(tmp, "wb") as f:
        f.write(target)
    r = subprocess.run([exe, "stamp", tmp], capture_output=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("ots stamp: %s" % r.stderr.decode("utf-8", "replace").strip())
    made = tmp + ".ots"
    path = layout.anchor_file(date, "opentimestamps", "ots")
    os.replace(made, path)
    os.remove(tmp)
    return {"path": path}


def _stamp_feed(target: bytes, layout: store.Layout, date: str,
                config: dict) -> dict:
    """Публичная лента с добавлением в конец.

    Смысл появляется только тогда, когда файл публикуется вовне (например,
    коммитится в публичный репозиторий). Лента, лежащая внутри того же
    каталога, что и журнал, раздвоение не обнаруживает — она под контролем той
    же стороны. Поэтому путь по умолчанию помечен как не опубликованный.
    """
    path = config.get("feed_path") or os.path.join(layout.anchors_dir(), "feed.jsonl")
    published = bool(config.get("feed_path"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    prev, seq = core.ZERO32, 0
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    e = json.loads(line)
                    prev, seq = bytes.fromhex(e["entry"]), e["seq"]
    entry = core.H(b"aihash/feed/1", core.lp(date.encode()), target, prev)
    rec = {"seq": seq + 1, "date": date, "target": target.hex(),
           "prev": prev.hex(), "entry": entry.hex()}
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return {"path": path, "entry": entry.hex(), "published": published}


_STAMPERS = {"rfc3161": _stamp_rfc3161, "opentimestamps": _stamp_ots,
             "feed": _stamp_feed}


# --- проверка ---------------------------------------------------------------


def verify_file(path: str, target: bytes, config: Optional[dict] = None,
                date: Optional[str] = None) -> dict:
    """Проверить пломбу по файлу. Сеть не используется.

    Кроме статуса результат несёт `placed`: **установлено ли**, что пломба
    поставлена именно на эту отметку. Без этого признака «не проверена» сливает
    два разных ответа — «пломбы за эти сутки нет» и «пломба стоит, но
    подтвердить её нечем», — а весь смысл раздела 7.1 спецификации в том, чтобы
    их различать.

    Планка намеренно высокая: `placed` ставится там, где принадлежность пломбы
    отметке доказана (сырые байты штампа, запись в ленте, разобранный ответ
    ots), а не там, где в каталоге просто лежит подходяще названный файл. Иначе
    любой файл, положенный в `anchors/`, смягчал бы вердикт.
    """
    config = config or {}
    name = os.path.basename(path)
    if name == "feed.jsonl":
        res = _verify_feed(path, target, date)
    elif name.endswith(".rfc3161.tsr"):
        res = _verify_rfc3161(path, target, config)
    elif name.endswith(".opentimestamps.ots"):
        res = _verify_ots(path, target, config)
    else:
        # Файл в anchors/ есть, а что это — неизвестно. Ни принадлежность
        # отметке, ни сам факт постановки пломбы отсюда не следуют.
        res = {"type": "unknown", "status": UNVERIFIED, "path": path,
               "detail": "неизвестный тип пломбы — пропущена, но не засчитана"}
    res.setdefault("placed", False)
    return res


def _verify_feed(path: str, target: bytes,
                 date: Optional[str] = None) -> dict:
    """Проверка публичной ленты.

    Различаются три исхода, и путать их нельзя:

      нет записей за эти сутки          — пломба не поставлена (не подделка)
      есть запись, отпечаток другой     — опубликовано другое: ПОДДЕЛКА
      две записи за сутки с разными
      отпечатками                       — раздвоение журнала: ПОДДЕЛКА

    Вторая строка — единственное, ради чего лента и заводится. Если считать её
    просто «не запечатано», то противник, пересчитавший журнал целиком, пройдёт
    проверку: внутри всё сойдётся, а расхождение с опубликованным никто не
    заметит.
    """
    prev = core.ZERO32
    found = None
    same_date = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return {"type": "feed", "status": FAILED, "path": path,
                        "detail": "запись ленты %d не разбирается" % n}
            if e.get("prev") != prev.hex():
                return {"type": "feed", "status": FAILED, "path": path,
                        "detail": "лента порвана на записи %d" % n}
            want = core.H(b"aihash/feed/1", core.lp(e["date"].encode()),
                          bytes.fromhex(e["target"]), prev)
            if want.hex() != e["entry"]:
                return {"type": "feed", "status": FAILED, "path": path,
                        "detail": "отпечаток записи ленты %d не сходится" % n}
            prev = want
            if date is None or e["date"] == date:
                same_date.append(e)
            if e["target"] == target.hex():
                found = e

    distinct = {e["target"] for e in same_date}
    if len(distinct) > 1:
        return {"type": "feed", "status": FAILED, "path": path,
                "detail": "за эти сутки в ленте опубликовано %d разных отметок "
                          "— раздвоение журнала" % len(distinct)}
    if found is not None:
        return {"type": "feed", "status": OK, "path": path, "placed": True,
                "detail": "запись %d в ленте; сила пломбы зависит от того, "
                          "опубликована ли лента вовне" % found["seq"]}
    if same_date:
        return {"type": "feed", "status": FAILED, "path": path,
                "detail": "за эти сутки в ленте опубликована ДРУГАЯ отметка "
                          "(%s…) — журнал не совпадает с опубликованным"
                          % same_date[0]["target"][:16]}
    # Лента цела, но этих суток в ней нет: пломба не была поставлена.
    return {"type": "feed", "status": UNVERIFIED, "path": path, "placed": False,
            "detail": "лента цела, но этих суток в ней нет — пломба лентой "
                      "не поставлена"}


def _verify_rfc3161(path: str, target: bytes, config: dict) -> dict:
    """Проверка штампа времени RFC 3161.

    Принадлежность штампа именно этой суточной отметке проверяется по сырым
    байтам ответа: отпечаток лежит в DER как есть. Разбирать для этого
    текстовый вывод `openssl ts -reply -text` нельзя — он печатает дамп с
    отступами и ASCII-колонкой, а не сплошной hex, и такая проверка ложно
    обвиняет исправный штамп. Ложное обвинение — худший отказ, какой этот
    продукт может выдать.

    Доверие берётся только из вшитого набора корней (`trust.py`) или из явного
    `--tsa-ca`. Ни сертификат из пакета, ни корень, вложенный в сам штамп, в
    построении доверия не участвуют: они приехали вместе с уликой.
    """
    with open(path, "rb") as f:
        data = f.read()
    if target not in data:
        return {"type": "rfc3161", "status": FAILED, "path": path,
                "detail": "штамп поставлен не на эту суточную отметку"}

    # Ниже этой строки принадлежность штампа отметке уже доказана сырыми
    # байтами: пломба за эти сутки поставлена, вопрос только в подписи.
    placed = {"type": "rfc3161", "path": path, "placed": True}

    openssl = shutil.which("openssl")
    if openssl is None:
        return dict(placed, status=UNVERIFIED,
                    detail="штамп относится к этой отметке, но openssl не "
                           "найден — подпись службы не проверена")

    ts = None
    info = _run([openssl, "ts", "-reply", "-in", path, "-text"])
    if info is not None and info.returncode == 0:
        ts = _extract(info.stdout.decode("utf-8", "replace"), "Time stamp:")

    override = config.get("tsa_ca")
    if override and os.path.exists(override):
        return _verify_signature(openssl, path, target, config, override,
                                 dict(placed, time=ts),
                                 origin="переопределение --tsa-ca")

    store = trust_mod.store_for(config)
    if store is None:
        return dict(placed, status=UNVERIFIED, time=ts,
                    detail="штамп относится к этой отметке, но набор корней "
                           "недоступен — подпись не проверена; укажите "
                           "корневой сертификат службы через --tsa-ca")

    # Корни пробуются по одному, чтобы вердикт мог назвать сработавший: «чем
    # именно вы это проверили» — законный вопрос стороны спора.
    tmpdir = tempfile.mkdtemp(prefix="aihash-trust-")
    try:
        for root in store.roots:
            ca_path = os.path.join(tmpdir, root.id + ".pem")
            with open(ca_path, "wb") as f:
                f.write(root.pem)
            res = _verify_signature(openssl, path, target, config, ca_path,
                                    dict(placed, time=ts),
                                    origin="%s версии %d, корень %s"
                                           % (store.origin, store.version, root.id))
            if res["status"] == OK:
                res["root"] = {"id": root.id, "name": root.name,
                               "sha256": root.sha256}
                res["trust_version"] = store.version
                return res
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Ни один корень не подошёл. Отличить «службы нет в наборе» от «подпись
    # плохая» можно было бы только разбором текста ошибок openssl — ровно тем
    # приёмом, который в этом проекте уже приводил к ложному обвинению. Поэтому
    # исход один и он мягкий: не подтверждена. Обвинять умеет только проверка
    # отпечатка выше, где мы читаем сырые байты сами.
    return _unknown_root(openssl, path, data, config, dict(placed, time=ts),
                         store)


def _run(cmd, **kw):
    """Вызов внешней программы, который не имеет права уронить верификатор."""
    try:
        return subprocess.run(cmd, capture_output=True, timeout=30, **kw)
    except (OSError, subprocess.SubprocessError):
        return None


def _verify_signature(openssl: str, path: str, target: bytes, config: dict,
                      ca_path: str, base: dict, origin: str) -> dict:
    cmd = [openssl, "ts", "-verify", "-digest", target.hex(), "-in", path,
           "-CAfile", ca_path]
    untrusted = config.get("tsa_untrusted")
    if untrusted and os.path.exists(untrusted):
        cmd += ["-untrusted", untrusted]
    v = _run(cmd)
    if v is None or v.returncode != 0:
        return dict(base, status=UNVERIFIED,
                    detail="подпись не сошлась с %s" % origin)
    return dict(base, status=OK,
                detail="подпись службы штампов проверена (%s)" % origin)


def _unknown_root(openssl: str, path: str, data: bytes, config: dict,
                  base: dict, store) -> dict:
    """Корня для этого штампа в наборе нет.

    Получателю мало сказать «не подтверждена»: он должен узнать, какой именно
    сертификат ему нужен. Отпечаток берётся из материала, приехавшего вместе с
    уликой, и потому назван предъявленным, а не доверенным: он говорит, что
    искать, и ничего не заверяет.
    """
    presented = _presented_roots(openssl, path, config)

    # Единственный случай, когда обвинение честно: предъявленный корень носит
    # то же имя, что известный нам, но это другой ключ. Совпадение имени при
    # другом ключе — выдача себя за известную службу, а не незнакомая служба.
    #
    # Остаточный риск ложного обвинения: перевыпуск корня той же службой с тем
    # же именем и НОВЫМ ключом выглядит отсюда так же. Перевыпуск с прежним
    # ключом (продление срока) ниже пропускается, он самый частый.
    for cert in presented:
        for root in store.roots:
            known = _root_info(openssl, root)
            if not known["subject"] or cert["subject"] != known["subject"]:
                continue
            if cert["sha256"] == root.sha256 or cert["pubkey"] == known["pubkey"]:
                continue
            return dict(base, status=FAILED,
                        detail="корень внутри штампа назвался известной службой "
                               "(%s), но это другой ключ: отпечаток %s… вместо "
                               "%s… — выдача себя за чужую службу"
                               % (root.id, cert["sha256"][:16], root.sha256[:16]))

    if presented:
        what = "; ".join(
            "%s (отпечаток %s…)" % (c["subject"] or "без имени", c["sha256"][:24])
            for c in presented)
        need = ("нужен корневой сертификат службы: %s. Возьмите его у самой "
                "службы, не из этого пакета, и повторите с "
                "--tsa-ca <файл.pem>" % what)
    else:
        need = ("какой именно корень нужен, из штампа определить не удалось; "
                "возьмите корневой сертификат службы у неё самой и повторите "
                "с --tsa-ca <файл.pem>")

    return dict(base, status=UNVERIFIED, trust_version=store.version,
                detail="штамп относится к этой отметке, но его службы нет в "
                       "наборе корней (версия %d): %s" % (store.version, need))


def _presented_roots(openssl: str, path: str, config: dict) -> list:
    """Сертификаты, предъявленные вместе с уликой: вложенные в сам штамп и
    приложенный к пакету файл. Доверия не создают — служат подсказкой, какой
    корень получателю искать."""
    out = []
    seen = set()
    blobs = []

    token = _run([openssl, "ts", "-reply", "-in", path, "-token_out"])
    if token is not None and token.returncode == 0 and token.stdout:
        certs = _run([openssl, "pkcs7", "-inform", "DER", "-print_certs"],
                     input=token.stdout)
        if certs is not None and certs.returncode == 0:
            blobs.append(certs.stdout)

    attached = config.get("presented_ca")
    if attached:
        blobs.append(attached if isinstance(attached, bytes)
                     else attached.encode("utf-8", "replace"))

    for blob in blobs:
        for der in trust_mod.pem_certs(blob):
            fp = trust_mod.fingerprint(der)
            if fp in seen:
                continue
            seen.add(fp)
            info = _cert_info(openssl, der)
            if info["self_signed"]:
                out.append(dict(info, sha256=fp))
    return out


def _cert_info(openssl: str, der: bytes) -> dict:
    """Имя, ключ и самоподписанность одного сертификата.

    Сравниваются строки, которые печатает сам openssl, — одна и та же программа
    с обеих сторон сравнения. Разбирать её вывод глазами тут не приходится:
    равенство строк не зависит от того, как она их форматирует.
    """
    subject = issuer = pubkey = ""
    r = _run([openssl, "x509", "-inform", "DER", "-noout", "-subject",
              "-issuer", "-nameopt", "RFC2253"], input=der)
    if r is not None and r.returncode == 0:
        text = r.stdout.decode("utf-8", "replace")
        subject = _extract(text, "subject=") or ""
        issuer = _extract(text, "issuer=") or ""
    p = _run([openssl, "x509", "-inform", "DER", "-noout", "-pubkey"], input=der)
    if p is not None and p.returncode == 0:
        pubkey = hashlib.sha256(p.stdout).hexdigest()
    return {"subject": subject, "issuer": issuer, "pubkey": pubkey,
            "self_signed": bool(subject) and subject == issuer}


def _root_info(openssl: str, root) -> dict:
    """Имя и ключ корня из набора, полученные тем же путём, что у предъявленного
    сертификата. Сравнивать строку из манифеста со строкой из openssl нельзя:
    расхождение в форматировании имени дало бы либо пропуск подмены, либо
    ложное обвинение."""
    ders = trust_mod.pem_certs(root.pem)
    if not ders:
        return {"subject": "", "pubkey": ""}
    return _cert_info(openssl, ders[0])


def _verify_ots(path: str, target: bytes, config: dict) -> dict:
    exe = shutil.which("ots")
    if exe is None:
        return {"type": "opentimestamps", "status": UNVERIFIED, "path": path,
                "detail": "клиент opentimestamps не установлен"}
    tmp = path + ".target"
    with open(tmp, "wb") as f:
        f.write(target)
    try:
        r = subprocess.run([exe, "verify", path, "-f", tmp],
                           capture_output=True, timeout=60)
        out = (r.stdout + r.stderr).decode("utf-8", "replace")
    finally:
        os.remove(tmp)
    if "Success" in out or "attests existence" in out:
        return {"type": "opentimestamps", "status": OK, "path": path,
                "placed": True, "detail": out.strip().splitlines()[-1][:200]}
    if "Pending" in out:
        # Клиенту скормлена сама отметка: он разобрал файл и подтвердил, что
        # это пломба именно над ней, — не хватает только включения в блок.
        return {"type": "opentimestamps", "status": UNVERIFIED, "path": path,
                "placed": True, "detail": "пломба ожидает включения в блок"}
    return {"type": "opentimestamps", "status": FAILED, "path": path,
            "detail": out.strip()[:200]}


def _extract(text: str, key: str) -> Optional[str]:
    for line in text.splitlines():
        if key in line:
            return line.split(key, 1)[1].strip()
    return None
