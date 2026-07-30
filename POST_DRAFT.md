# Черновик поста. НЕ ОПУБЛИКОВАН

Постит владелец, вручную.

**Про язык.** Hacker News и r/crypto англоязычные — русский текст там просто не
прочитают. Поэтому основной вариант ниже английский, под ним русский для
VC.ru, Хабра и телеграм-каналов. Репозиторий при этом русскоязычный; это
первое, обо что споткнётся англоязычный читатель, и решать, что с этим делать,
— владельцу. Вариант «оставить как есть» рабочий: `demo/` проверяется двумя
командами, а вывод понятен и без языка.

---

## Заголовки — два варианта

**Вариант 1 (что это делает):**
> Show HN: Aihash – tamper-evident logs for AI systems, with third-party seals

**Вариант 2 (что можно потрогать):**
> Show HN: Aihash – change one character in the demo log and the verifier says no

Первый точнее описывает продукт. Второй приглашает к действию и лучше ложится
на гифку в README. Я бы взял второй: на Show HN работает то, что можно
проверить за минуту, а не то, что можно понять за минуту.

---

## Текст (английский)

**Title:** Show HN: Aihash – change one character in the demo log and the verifier says no

Every company running an AI agent keeps logs of what it did. The problem shows
up the day a customer says "your bot promised me a refund" — you open the log,
it says something else, and the customer's lawyer points out that you control
that file. Nothing in an ordinary log proves it wasn't edited last night. The
logs are usually fine. What is missing is any way to show that.

Aihash makes the log provable. Every field of a record gets a fingerprint,
records are chained, a day of chain collapses into one value, and that value is
sealed by a third party — an RFC 3161 timestamp authority, OpenTimestamps, and
a public append-only feed. After the seal, changing anything is visible.

**Try it in a minute — the repo ships a real journal sealed by a real
timestamp authority:**

```bash
pip install aihash
git clone https://github.com/jacobb-del/aihash && cd aihash
aihash verify ./demo/journal
```

Then open `demo/journal/streams/voice-eu-3/segments/2026-07-29.jsonl`, change
the `3` in "в течение 3 дней" to a `5`, and run the same command. It names the
record that broke and exits 1. Nothing is mocked: the timestamp token in
`demo/journal/anchors/` came from freetsa.org, and you can check it with
`openssl ts -verify` without running a line of my code.

**Please try to break it.** The format is specified in FORMAT.md, there are
nine sets of test vectors in spec/, and four independent implementations
(Python, TypeScript, a static Go binary, and a single-file browser page) that
must agree byte for byte. The interesting attack surface is the format itself,
not the code — if you find a way to produce two different journals that verify
against the same seal, that is the bug I want to hear about.

**What it does not do**, stated plainly because I would rather lose a user than
oversell:

- It does not prove your records are **true**. A sealed lie is a sealed lie.
- It does not prove the log is **complete**. Anything never written leaves no trace.
- It does not prove **authorship** unless you add an optional signature.
- It does not stop **tail truncation between seals** — records made after the
  last seal can still be dropped silently. Shrinks with seal frequency.
- Signature checking today happens only in the Python SDK. The Go binary and
  the browser page verify that the timestamp covers this exact value, then say
  "seal is present but not confirmed here" — which is deliberately not the same
  answer as "no seal".
- No external cryptographic review yet. Everything so far was checked by me,
  and for a product whose whole value is evidentiary, that is not the same
  thing as independent scrutiny.

One design decision worth flagging, because it is the part I expect people to
argue with: the trust root ships **with the verifier, not with the evidence
bundle** — the way browsers ship CA roots, not the way a website ships its own.
A certificate attached to the bundle never establishes trust, because a forger
would attach their own root to their own forged stamp and vouch for themselves.
When a timestamp comes from an authority not in the bundled set, the verifier
says "present, not confirmed" and prints which certificate you need. It does
not say "forged". A company using a national TSA I have never heard of is
indistinguishable from a forger, and calling both of them liars is the failure
mode that kills trust in the tool.

Apache-2.0. https://github.com/jacobb-del/aihash

---

## Текст (русский)

**Заголовок:** Aihash — поменяйте один символ в demo-журнале, и проверка его назовёт

У всех, кто держит ИИ-агента, есть логи того, что он делал. Проблема
обнаруживается в день, когда клиент говорит «ваш бот обещал мне возврат»: вы
открываете лог, там написано другое, а юрист клиента замечает, что файл лежит
у вас и правится вами. Обычный лог никак не доказывает, что его не поправили
вчера вечером. Чаще всего логи в порядке — не хватает способа это показать.

Aihash делает журнал доказуемым. У каждого поля записи свой отпечаток, записи
связаны в цепь, цепь за сутки сворачивается в одну отметку, и на неё ставится
пломба у третьей стороны: штамп времени RFC 3161, OpenTimestamps и публичная
лента. После пломбы правка становится видна.

**Проверить за минуту — в репозитории лежит настоящий журнал с настоящим
штампом:**

```bash
pip install aihash
git clone https://github.com/jacobb-del/aihash && cd aihash
aihash verify ./demo/journal
```

Потом откройте `demo/journal/streams/voice-eu-3/segments/2026-07-29.jsonl`,
поменяйте `3` на `5` в «в течение 3 дней» и повторите ту же команду. Она
назовёт запись, на которой всё разошлось, и вернёт код 1. Ничего не
имитировано: штамп в `demo/journal/anchors/` получен от freetsa.org, и его
можно проверить командой `openssl ts -verify`, не запуская ни строчки моего
кода.

**Ищите дыры.** Формат описан в FORMAT.md, в spec/ лежат девять наборов
тестовых векторов, и четыре независимые реализации обязаны сходиться побайтово.
Интересна не столько реализация, сколько сам формат: если найдёте способ
собрать два разных журнала, сходящихся с одной пломбой, — это ровно то, о чём
я хочу услышать.

**Чего продукт не делает** — прямым текстом, потому что потерять пользователя
дешевле, чем переоценить себя:

- Не доказывает, что записи **правдивы**. Запечатанная ложь остаётся ложью.
- Не доказывает, что журнал **полон**. То, чего не записали, следа не оставляет.
- Не доказывает **авторство** без отдельной подписи.
- Не защищает от **обрезки хвоста между пломбами**: записи после последней
  пломбы можно молча удалить. Окно сокращается частотой пломб.
- Подпись штампа сегодня сверяет только Python SDK. Бинарь и страница для
  браузера проверяют, что штамп относится именно к этой отметке, и говорят
  «пломба стоит, но здесь не подтверждена» — намеренно не то же самое, что
  «пломбы нет».
- Внешнего криптографического разбора не было. Всё проверял я сам, а для
  продукта, чья ценность целиком в доказательности, это не заменяет
  независимый разбор.

Одно решение, вокруг которого, думаю, будет спор: корень доверия едет **с
верификатором, а не с пакетом доказательства** — как у браузеров. Сертификат,
приложенный к улике, доверия не создаёт: иначе подделыватель приложил бы к
своему поддельному штампу свой корень и заверил бы сам себя. Если штамп
поставлен службой, которой нет во вшитом наборе, верификатор говорит «стоит, не
подтверждена» и печатает, какой сертификат нужен. Он не говорит «подделка»:
компания с национальной службой, о которой я не слышал, неотличима отсюда от
подделывателя, а объявить обоих лжецами — самый быстрый способ убить доверие к
инструменту.

Apache-2.0. https://github.com/jacobb-del/aihash

---

## Проверено перед постом

- `pip install aihash` с боевого PyPI в чистом контейнере — ставится, `assets`
  содержит и набор корней, и верификатор.
- `git clone` публичного репозитория и `aihash verify ./demo/journal` — код 0,
  «Запечатано суток: 1».
- Правка одного символа — «НЕ СХОДИТСЯ», код 1.
- Гифка и ссылки в README открываются по абсолютным адресам (200).

Обе команды из поста скопированы из настоящего прогона, а не написаны на глаз.
