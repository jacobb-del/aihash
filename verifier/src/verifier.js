/* Независимый верификатор формата aihash/1.
 *
 * Ни одной зависимости. Ни одного обращения в сеть. Ни одной строки, которую
 * нельзя прочитать глазами: SHA-256 реализован здесь же, а не взят из
 * crypto.subtle, потому что тот недоступен при открытии файла с диска в части
 * браузеров, а верификатор обязан работать двойным щелчком по файлу.
 *
 * Этот же файл собирается в verify.html (для юриста) и в aihash-verify.js
 * (для инженера и CI). Источник один, чтобы они не разъехались.
 */
(function (root) {
  "use strict";

  // --- SHA-256 -------------------------------------------------------------

  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(msg) {
    var h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    var l = msg.length;
    var total = ((l + 9 + 63) >> 6) << 6;
    var b = new Uint8Array(total);
    b.set(msg);
    b[l] = 0x80;
    var bits = l * 8;
    var hi = Math.floor(bits / 4294967296), lo = bits >>> 0;
    b[total - 8] = (hi >>> 24) & 0xff; b[total - 7] = (hi >>> 16) & 0xff;
    b[total - 6] = (hi >>> 8) & 0xff;  b[total - 5] = hi & 0xff;
    b[total - 4] = (lo >>> 24) & 0xff; b[total - 3] = (lo >>> 16) & 0xff;
    b[total - 2] = (lo >>> 8) & 0xff;  b[total - 1] = lo & 0xff;

    var w = new Uint32Array(64), i, j, t1, t2, s0, s1, ch, maj;
    for (i = 0; i < total; i += 64) {
      for (j = 0; j < 16; j++) {
        w[j] = (b[i + 4 * j] << 24) | (b[i + 4 * j + 1] << 16) |
               (b[i + 4 * j + 2] << 8) | b[i + 4 * j + 3];
      }
      for (j = 16; j < 64; j++) {
        s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      var a = h0, bb = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
      for (j = 0; j < 64; j++) {
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        ch = (e & f) ^ (~e & g);
        t1 = (hh + s1 + ch + K[j] + w[j]) | 0;
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        maj = (a & bb) ^ (a & c) ^ (bb & c);
        t2 = (s0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = bb; bb = a; a = (t1 + t2) | 0;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + bb) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
      h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
    }
    var out = new Uint8Array(32), hs = [h0, h1, h2, h3, h4, h5, h6, h7];
    for (i = 0; i < 8; i++) {
      out[4 * i] = (hs[i] >>> 24) & 0xff; out[4 * i + 1] = (hs[i] >>> 16) & 0xff;
      out[4 * i + 2] = (hs[i] >>> 8) & 0xff; out[4 * i + 3] = hs[i] & 0xff;
    }
    return out;
  }

  // --- байты ---------------------------------------------------------------

  function concat(parts) {
    var n = 0, i;
    for (i = 0; i < parts.length; i++) n += parts[i].length;
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }

  function H() { return sha256(concat(Array.prototype.slice.call(arguments))); }

  function varint(n) {
    if (n < 0) throw new Error("varint: отрицательное значение");
    var out = [];
    for (;;) {
      var b = n % 128;
      n = Math.floor(n / 128);
      if (n) out.push(b | 0x80); else { out.push(b); break; }
    }
    return new Uint8Array(out);
  }

  function lp(b) { return concat([varint(b.length), b]); }
  function tag(t) { return new Uint8Array([t]); }

  function utf8(s) { return new TextEncoder().encode(s); }
  function fromUtf8(b) { return new TextDecoder("utf-8").decode(b); }

  function hex(b) {
    var s = "";
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
  }

  function unhex(s) {
    if (s.length % 2) throw new Error("нечётная длина hex");
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
    return out;
  }

  var B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function unb64(s) {
    s = s.replace(/[\r\n\s]/g, "");
    var pad = 0;
    while (s.length && s[s.length - 1] === "=") { pad++; s = s.slice(0, -1); }
    var out = new Uint8Array(Math.floor(s.length * 6 / 8)), acc = 0, bits = 0, o = 0;
    for (var i = 0; i < s.length; i++) {
      var v = B64.indexOf(s[i]);
      if (v < 0) throw new Error("недопустимый символ base64");
      acc = (acc << 6) | v; bits += 6;
      if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xff; }
    }
    return out.subarray(0, o);
  }

  function bytesLess(a, b) {
    var n = Math.min(a.length, b.length);
    for (var i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  }

  // --- примитивы формата ---------------------------------------------------

  var T_FIELD = 0x01, T_NODE = 0x02, T_LINK = 0x03, T_GENESIS = 0x04,
      T_SEGLEAF = 0x05, T_SEGCKPT = 0x06, T_DAYLEAF = 0x07, T_DAYCKPT = 0x08;

  function fieldLeaf(name, salt, value) {
    var nb = utf8(name);
    if (nb.length < 1 || nb.length > 255) throw new Error("длина имени поля вне 1..255");
    if (salt.length !== 16) throw new Error("соль должна быть 16 байт");
    return H(tag(T_FIELD), lp(nb), lp(salt), lp(value));
  }

  function split(n) { var k = 1; while (k * 2 < n) k *= 2; return k; }

  function mth(leaves) {
    if (leaves.length === 0) throw new Error("пустое дерево запрещено");
    if (leaves.length === 1) return leaves[0];
    var k = split(leaves.length);
    return H(tag(T_NODE), mth(leaves.slice(0, k)), mth(leaves.slice(k)));
  }

  function applyPath(leaf, path) {
    var cur = leaf;
    for (var i = 0; i < path.length; i++) {
      var s = path[i], sib = unhex(s.h);
      if (sib.length !== 32) throw new Error("сосед в пути должен быть 32 байта");
      if (s.side === "right") cur = H(tag(T_NODE), cur, sib);
      else if (s.side === "left") cur = H(tag(T_NODE), sib, cur);
      else throw new Error("сторона должна быть left или right");
    }
    return cur;
  }

  function rawValue(f) {
    if ("s" in f && "b" in f) throw new Error("поле " + f.name + ": s и b одновременно");
    if ("s" in f) return utf8(f.s);
    if ("b" in f) return unb64(f.b);
    throw new Error("поле " + f.name + ": нет ни s, ни b");
  }

  function contentRoot(fields) {
    if (!fields || !fields.length) throw new Error("запись без полей");
    var items = [], seen = {};
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i], nb = utf8(f.name);
      if (seen[f.name]) throw new Error("повтор имени поля: " + f.name);
      seen[f.name] = true;
      var leaf;
      if ("leaf" in f) {
        if ("salt" in f || "s" in f || "b" in f)
          throw new Error("вычеркнутое поле " + f.name + " сохранило соль или значение");
        leaf = unhex(f.leaf);
        if (leaf.length !== 32) throw new Error("лист должен быть 32 байта");
      } else {
        leaf = fieldLeaf(f.name, unhex(f.salt), rawValue(f));
      }
      items.push([nb, leaf]);
    }
    items.sort(function (a, b) { return bytesLess(a[0], b[0]); });
    return mth(items.map(function (x) { return x[1]; }));
  }

  function genesis(streamId) {
    return H(tag(T_GENESIS), lp(utf8(streamId)), lp(utf8("aihash/1")));
  }

  function link(prev, seq, croot, ts) {
    if (seq < 1) throw new Error("seq начинается с 1");
    return H(tag(T_LINK), prev, varint(seq), croot, varint(ts));
  }

  function segLeaf(l) { return H(tag(T_SEGLEAF), l); }
  function dayLeaf(c) { return H(tag(T_DAYLEAF), c); }

  function segCkpt(s) {
    if (s.last_seq - s.first_seq + 1 !== s.count)
      throw new Error("count не совпадает с диапазоном seq");
    return H(tag(T_SEGCKPT), lp(utf8(s.stream_id)), lp(utf8(s.period_id)),
             varint(s.first_seq), varint(s.last_seq), varint(s.count),
             unhex(s.link_before), unhex(s.link_last), unhex(s.segment_root),
             unhex(s.prev_checkpoint));
  }

  function dayCkpt(d) {
    if (!d.streams.length) throw new Error("сутки без потоков");
    return H(tag(T_DAYCKPT), lp(utf8(d.realm_id)), lp(utf8(d.date)),
             varint(d.streams.length), unhex(d.day_root), unhex(d.prev_checkpoint));
  }

  // --- чтение zip без распаковщика ----------------------------------------
  // Пакет .seal пишется без сжатия именно ради этого: чтобы верификатору не
  // требовался inflate и он оставался читаемым целиком.


  /* Верификатор по определению обрабатывает файл, полученный от
   * противоположной стороны. Без пределов присланный архив в мегабайт кладёт
   * машину проверяющего. Законный пакет на порядки меньше. */
  var MAX_ENTRIES = 512, MAX_ENTRY_BYTES = 64 * 1024 * 1024,
      MAX_TOTAL_BYTES = 128 * 1024 * 1024;

  function safeName(name) {
    var n = name.replace(/\\/g, "/");
    if (n.charAt(0) === "/") throw new Error("недопустимое имя в архиве: " + name);
    var parts = n.split("/");
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === ".." || parts[i] === ".") {
        throw new Error("имя в архиве выходит за его пределы: " + name);
      }
    }
    return name;
  }

  function u16(b, o) {
    if (o + 2 > b.length) throw new Error("архив обрывается");
    return b[o] | (b[o + 1] << 8);
  }
  function u32(b, o) {
    if (o + 4 > b.length) throw new Error("архив обрывается");
    return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + b[o + 3] * 16777216;
  }

  function readZip(buf) {
    var i, eocd = -1;
    for (i = buf.length - 22; i >= 0 && i > buf.length - 65558; i--) {
      if (u32(buf, i) === 0x06054b50) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error("это не zip-архив");
    var count = u16(buf, eocd + 10), off = u32(buf, eocd + 16), entries = [];
    if (count > MAX_ENTRIES) {
      throw new Error("в архиве " + count + " записей, предел " + MAX_ENTRIES);
    }
    var total = 0;
    for (i = 0; i < count; i++) {
      if (u32(buf, off) !== 0x02014b50) throw new Error("повреждён каталог архива");
      var method = u16(buf, off + 10), csize = u32(buf, off + 20),
          size = u32(buf, off + 24), nlen = u16(buf, off + 28),
          elen = u16(buf, off + 30), clen = u16(buf, off + 32),
          lho = u32(buf, off + 42);
      var name = safeName(fromUtf8(buf.subarray(off + 46, off + 46 + nlen)));
      if (size > MAX_ENTRY_BYTES) {
        throw new Error(name + ": заявлено " + size + " байт, предел "
                        + MAX_ENTRY_BYTES + " — архивная бомба");
      }
      total += size;
      if (total > MAX_TOTAL_BYTES) {
        throw new Error("суммарный размер архива превышает " + MAX_TOTAL_BYTES);
      }
      if (u32(buf, lho) !== 0x04034b50) throw new Error("повреждён заголовок файла");
      var dataOff = lho + 30 + u16(buf, lho + 26) + u16(buf, lho + 28);
      if (dataOff + csize > buf.length) throw new Error("запись " + name + " обрывается");
      entries.push({ name: name, method: method, size: size,
                     data: buf.subarray(dataOff, dataOff + csize) });
      off += 46 + nlen + elen + clen;
    }
    return entries;
  }

  function inflateIfNeeded(e) {
    if (e.method === 0) return Promise.resolve(e.data);
    // Заголовок архива может лгать о размере, поэтому распакованное
    // проверяется ещё раз по факту.
    if (typeof DecompressionStream === "undefined")
      return Promise.reject(new Error(
        "файл " + e.name + " сжат, а распаковщик недоступен"));
    var ds = new DecompressionStream("deflate-raw");
    var w = ds.writable.getWriter();
    w.write(e.data); w.close();
    return new Response(ds.readable).arrayBuffer().then(function (a) {
      if (a.byteLength > MAX_ENTRY_BYTES) {
        throw new Error(e.name + ": распакованный размер превышает предел");
      }
      return new Uint8Array(a);
    });
  }

  function loadBundle(bytes) {
    var entries = readZip(bytes), files = {};
    return entries.reduce(function (p, e) {
      return p.then(function () {
        return inflateIfNeeded(e).then(function (d) { files[e.name] = d; });
      });
    }, Promise.resolve()).then(function () { return files; });
  }

  // --- пломбы --------------------------------------------------------------

  /* Различаются три исхода, и путать их нельзя:
   *   нет записей за эти сутки       — пломба не поставлена (не подделка)
   *   есть запись, отпечаток другой  — опубликовано другое: ПОДДЕЛКА
   *   две записи с разными отметками — раздвоение журнала: ПОДДЕЛКА
   * Вторая строка — единственное, ради чего лента и заводится. */
  function verifyFeed(text, target, date) {
    var lines = text.split("\n").filter(function (x) { return x.trim(); });
    var prev = new Uint8Array(32), found = null, sameDate = [];
    for (var i = 0; i < lines.length; i++) {
      var e;
      try { e = JSON.parse(lines[i]); }
      catch (err) {
        return { type: "feed", status: "failed",
                 detail: "запись ленты " + (i + 1) + " не разбирается" };
      }
      if (e.prev !== hex(prev)) {
        return { type: "feed", status: "failed",
                 detail: "лента порвана на записи " + (i + 1) };
      }
      var want = H(utf8("aihash/feed/1"), lp(utf8(e.date)), unhex(e.target), prev);
      if (hex(want) !== e.entry) {
        return { type: "feed", status: "failed",
                 detail: "отпечаток записи ленты " + (i + 1) + " не сходится" };
      }
      prev = want;
      if (date === undefined || e.date === date) sameDate.push(e);
      if (e.target === hex(target)) found = e;
    }

    var distinct = {}, n = 0, k;
    for (k = 0; k < sameDate.length; k++) {
      if (!distinct[sameDate[k].target]) { distinct[sameDate[k].target] = 1; n++; }
    }
    if (n > 1) {
      return { type: "feed", status: "failed",
               detail: "за эти сутки в ленте опубликовано " + n
                       + " разных отметок — раздвоение журнала" };
    }
    if (found) {
      return { type: "feed", status: "ok", placed: true,
               detail: "запись " + found.seq + " в ленте; сила пломбы зависит "
                       + "от того, опубликована ли лента вовне" };
    }
    if (sameDate.length) {
      return { type: "feed", status: "failed",
               detail: "за эти сутки в ленте опубликована ДРУГАЯ отметка ("
                       + sameDate[0].target.slice(0, 16)
                       + "…) — журнал не совпадает с опубликованным" };
    }
    // Это «пломбы нет», а не «пломба не подтверждена»: placed остаётся false.
    return { type: "feed", status: "unverified", placed: false,
             detail: "лента цела, но этих суток в ней нет — пломба лентой "
                     + "не поставлена" };
  }

  function contains(hay, needle) {
    for (var i = 0; i + needle.length <= hay.length; i++) {
      var hit = true;
      for (var j = 0; j < needle.length; j++) {
        if (hay[i + j] !== needle[j]) { hit = false; break; }
      }
      if (hit) return true;
    }
    return false;
  }

  /* Проверка одной пломбы по её байтам. Типы, которые нельзя подтвердить
   * офлайн без стороннего материала, возвращают «не проверена», а не
   * «в порядке».
   *
   * Кроме статуса результат несёт placed: установлено ли, что пломба
   * поставлена именно на эту отметку. Без этого «не проверена» сливает два
   * разных ответа — «пломбы за эти сутки нет» и «пломба стоит, но подтвердить
   * её нечем». Здесь это особенно важно: подпись штампа RFC 3161 в браузере не
   * проверяется никогда.
   *
   * Планка намеренно высокая: признак ставится там, где принадлежность пломбы
   * отметке доказана, а не там, где в архиве просто лежит подходяще названный
   * файл. Иначе любой файл, положенный в anchors/, смягчал бы вердикт. */
  function verifyAnchorBlob(name, data, target, date) {
    var res = anchorBlob(name, data, target, date);
    if (res.placed === undefined) res.placed = false;
    return res;
  }

  function anchorBlob(name, data, target, date) {
    var base = name.replace(/^.*\//, "");
    if (base === "feed.jsonl") return verifyFeed(fromUtf8(data), target, date);
    if (/\.rfc3161\.tsr$/.test(base)) {
      // Отпечаток лежит в DER как есть: принадлежность штампа этой отметке
      // проверяется по сырым байтам, а не по текстовому дампу openssl.
      // Сойдясь по сырым байтам, штамп доказывает, что пломба за эти сутки
      // поставлена: непроверенной остаётся только подпись службы.
      return contains(data, target)
        ? { type: "rfc3161", status: "unverified", placed: true,
            detail: "штамп относится к этой отметке; подпись службы "
                    + "проверяется командой aihash-verify" }
        : { type: "rfc3161", status: "failed",
            detail: "штамп поставлен не на эту суточную отметку" };
    }
    if (/\.opentimestamps\.ots$/.test(base)) {
      return { type: "opentimestamps", status: "unverified",
               detail: "требуется клиент opentimestamps" };
    }
    return { type: base, status: "unverified",
             detail: "неизвестный тип пломбы — не засчитана" };
  }

  function verifyAnchors(files, target, date) {
    var out = [];
    for (var name in files) {
      if (name.indexOf("anchors/") !== 0) continue;
      out.push(verifyAnchorBlob(name, files[name], target, date));
    }
    return out;
  }

  /* Три исхода, а не два. Граница между «пломбы нет» и «пломба не
   * подтверждена» проходит по тому, поставлена ли пломба вообще, а не по
   * тому, удалось ли её проверить. */
  function dayStatus(anchors) {
    var status = "open", i;
    for (i = 0; i < anchors.length; i++) {
      if (anchors[i].status === "ok") return "sealed";
      if (anchors[i].status === "unverified" && anchors[i].placed)
        status = "unverified";
    }
    return status;
  }

  function beaconLowerBound(round, source) {
    if (source !== "drand:quicknet") return null;
    return (1692803367 + (round - 1) * 3) * 1000;
  }

  // --- проверка пакета -----------------------------------------------------

  function verify(bytes) {
    return loadBundle(bytes).then(function (files) {
      var out = { status: "broken", checks: [], problems: [], anchors: [] };
      function need(name) {
        if (!files[name]) throw new Error("в пакете нет " + name);
        return JSON.parse(fromUtf8(files[name]));
      }
      function ok(label, cond, detail) {
        out.checks.push({ label: label, ok: !!cond, detail: detail || "" });
        if (!cond) out.problems.push(label + (detail ? ": " + detail : ""));
        return !!cond;
      }

      var manifest, records, proofs, segment, day;
      try {
        manifest = need("manifest.json");
        proofs = need("proofs.json");
        segment = need("segment.json");
        day = need("day.json");
        records = fromUtf8(files["records.jsonl"]).split("\n")
          .filter(function (x) { return x.trim(); })
          .map(function (x, i) {
            var rec = JSON.parse(x);
            if (!rec || typeof rec.seq !== "number" || !Array.isArray(rec.fields)) {
              throw new Error("records.jsonl строка " + (i + 1)
                              + ": нет seq или полей");
            }
            return rec;
          });
        if (!records.length) throw new Error("в пакете нет ни одной раскрытой записи");
      } catch (e) {
        out.problems.push(e.message);
        return out;
      }

      if (!ok("версия формата", manifest.format === "aihash/1", manifest.format))
        return out;

      for (var i = 0; i < records.length; i++) {
        var rec = records[i], p = proofs.records[String(rec.seq)];
        if (!p) { ok("запись seq=" + rec.seq + ": путь в пакете", false); return out; }
        var croot;
        try { croot = contentRoot(rec.fields); }
        catch (e) { ok("запись seq=" + rec.seq + ": поля", false, e.message); return out; }
        var l = link(unhex(p.prev_link), rec.seq, croot, rec.ts);
        if (!ok("запись seq=" + rec.seq + ": содержимое и звено", hex(l) === p.link))
          return out;
        var got = applyPath(segLeaf(l), p.segment_path);
        if (!ok("запись seq=" + rec.seq + ": путь до корня отрезка",
                hex(got) === segment.segment_root)) return out;
      }

      var ck;
      try { ck = segCkpt(segment); }
      catch (e) { ok("отметка отрезка", false, e.message); return out; }
      if (!ok("отметка отрезка", hex(ck) === segment.checkpoint)) return out;

      var droot = applyPath(dayLeaf(ck), proofs.day_path);
      if (!ok("путь до суточного корня", hex(droot) === day.day_root)) return out;

      var dck = dayCkpt(day);
      if (!ok("суточная отметка", hex(dck) === day.day_checkpoint)) return out;

      out.anchors = verifyAnchors(files, dck, day.date);
      for (var j = 0; j < out.anchors.length; j++) {
        if (out.anchors[j].status === "failed")
          ok("пломба " + out.anchors[j].type, false, out.anchors[j].detail);
      }
      if (out.problems.length) return out;

      out.status = dayStatus(out.anchors);
      out.manifest = manifest;
      out.records = records;
      out.segment = segment;
      out.day = day;
      out.lower = manifest.beacon
        ? beaconLowerBound(parseInt(manifest.beacon.round, 10), manifest.beacon.source)
        : null;
      out.lowerSource = manifest.beacon
        ? manifest.beacon.source + " раунд " + manifest.beacon.round : null;
      out.report = files["report.html"] ? fromUtf8(files["report.html"]) : null;
      return out;
    });
  }

  root.aihash = {
    sha256: sha256, hex: hex, unhex: unhex, varint: varint, utf8: utf8,
    fieldLeaf: fieldLeaf, mth: mth, applyPath: applyPath,
    contentRoot: contentRoot, genesis: genesis, link: link,
    segLeaf: segLeaf, dayLeaf: dayLeaf, segCkpt: segCkpt, dayCkpt: dayCkpt,
    readZip: readZip, verify: verify, unb64: unb64,
    verifyAnchorBlob: verifyAnchorBlob, verifyFeed: verifyFeed,
    beaconLowerBound: beaconLowerBound, FORMAT: "aihash/1"
  };
})(typeof module !== "undefined" && module.exports ? module.exports : this);
