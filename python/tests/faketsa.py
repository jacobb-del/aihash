"""Настоящая поддельная служба штампов времени.

Нужна затем, что слабая подделка ничего не проверяет. Противник не подсовывает
битый файл — он поднимает свой удостоверяющий центр, выписывает себе сертификат
службы штампов и штампует им переписанный журнал. Полученный .tsr криптографически
безупречен: `openssl ts -verify` принимает его без единого замечания, если дать
ему корень этого центра.

Ровно это здесь и собирается — openssl умеет быть службой штампов. Единственное,
чего противник не может, — попасть своим корнем в набор, который получатель взял
отдельно от него.
"""

from __future__ import annotations

import os
import shutil
import subprocess

CONFIG = """\
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = {dir}/serial
signer_cert = {dir}/tsa.crt
certs = {dir}/ca.crt
signer_key = {dir}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
[ tsa_ext ]
extendedKeyUsage = critical,timeStamping
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
"""

DEFAULT_SUBJECT = "/O=Poddelka TSA/OU=Root CA/CN=poddelka.example"


def available() -> bool:
    return shutil.which("openssl") is not None


def _run(args, **kw) -> subprocess.CompletedProcess:
    r = subprocess.run(args, capture_output=True, timeout=120, **kw)
    if r.returncode != 0:
        raise RuntimeError("%s: %s" % (args[:3],
                                       r.stderr.decode("utf-8", "replace")[:400]))
    return r


class FakeTSA:
    """Свой удостоверяющий центр и своя служба штампов в одном каталоге."""

    def __init__(self, directory: str, root_subject: str = DEFAULT_SUBJECT,
                 signer_subject: str = "/O=Poddelka TSA/OU=TSA/CN=poddelka.example"):
        self.dir = directory
        os.makedirs(self.dir, exist_ok=True)
        self.ca_cert = os.path.join(self.dir, "ca.crt")
        self.config = os.path.join(self.dir, "tsa.cnf")

        with open(os.path.join(self.dir, "serial"), "w") as f:
            f.write("01\n")
        with open(self.config, "w") as f:
            f.write(CONFIG.format(dir=self.dir))

        ca_key = os.path.join(self.dir, "ca.key")
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
              "-keyout", ca_key, "-out", self.ca_cert, "-days", "3650",
              "-subj", root_subject])

        tsa_key = os.path.join(self.dir, "tsa.key")
        csr = os.path.join(self.dir, "tsa.csr")
        _run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
              "-keyout", tsa_key, "-out", csr, "-subj", signer_subject])
        _run(["openssl", "x509", "-req", "-in", csr, "-CA", self.ca_cert,
              "-CAkey", ca_key, "-set_serial", "2", "-days", "3650",
              "-extfile", self.config, "-extensions", "tsa_ext",
              "-out", os.path.join(self.dir, "tsa.crt")])

    def stamp(self, digest_hex: str, out_path: str) -> str:
        """Штамп на произвольный отпечаток. Настоящий RFC 3161, чужая подпись."""
        query = os.path.join(self.dir, "q.tsq")
        _run(["openssl", "ts", "-query", "-digest", digest_hex, "-sha256",
              "-cert", "-out", query])
        _run(["openssl", "ts", "-reply", "-config", self.config,
              "-section", "tsa_config", "-queryfile", query, "-out", out_path])
        return out_path
