"""aihash — доказуемый журнал работы ИИ-системы.

Подключение в одну строку:

    import aihash
    log = aihash.open("./journal", realm="romashka-prod", stream="voice-eu-3")

    log.record({"actor": "assistant",
                "output.text": "возврат придёт в течение 5 дней",
                "config.model": "gpt-4o-2026-02-11"})

Дальше 364 дня в году ничего не происходит. В день, когда прилетела претензия:

    aihash seal --root ./journal
    aihash explain --root ./journal --stream voice-eu-3 --seq 4 --out ep.seal

Проверка выполняется у оппонента, офлайн, без обращения к вам:

    aihash verify ep.seal
"""

from .core import FORMAT_VERSION, FormatError
from .journal import BoundStream, Journal, Overflow, WriterFailed
from .verify import BROKEN, OPEN, SEALED, verify_bundle, verify_journal

__version__ = "0.1.0"

__all__ = ["open", "Journal", "BoundStream", "FormatError", "Overflow",
           "WriterFailed", "verify_journal", "verify_bundle",
           "FORMAT_VERSION", "SEALED", "OPEN", "BROKEN", "__version__"]

_builtin_open = open


def open(root: str, *, realm: str, stream: str, **kw) -> BoundStream:  # noqa: A001
    """Открыть журнал и привязаться к одному потоку.

    Параметры записи (все имеют разумные значения по умолчанию):
      queue_size      предел очереди; переполнение даёт Overflow, а не тихий сброс
      put_timeout     сколько ждать места в очереди, прежде чем поднять Overflow
      flush_interval  как часто сбрасывать на диск
      beacon_source   "drand" или None, чтобы не обращаться в сеть
    """
    return BoundStream(Journal(root, realm, **kw), stream)
