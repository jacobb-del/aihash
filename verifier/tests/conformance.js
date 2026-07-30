/* Верификатор обязан сходиться с векторами этапа 0 побайтово — теми же
 * файлами, по которым проверяется Python. Это единственное, что не даёт двум
 * реализациям разъехаться.
 *
 *   node verifier/tests/conformance.js
 */
"use strict";
var fs = require("fs"), path = require("path");
var a = require("../src/verifier.js").aihash;

var V = path.join(__dirname, "..", "..", "spec", "vectors");
var pass = 0, fail = [];

function load(n) { return JSON.parse(fs.readFileSync(path.join(V, n + ".json"), "utf8")); }
function eq(label, got, want) {
  if (got === want) pass++;
  else fail.push(label + "\n    ожидалось " + want + "\n    получено  " + got);
}
function reject(label, fn) {
  try { fn(); fail.push("должно было быть отвергнуто: " + label); }
  catch (e) { pass++; }
}

load("01-varint").cases.forEach(function (c) {
  eq("varint(" + c.value + ")", a.hex(a.varint(c.value)), c.hex);
});

load("02-field-leaf").cases.forEach(function (c) {
  var v = "s" in c ? a.utf8(c.s) : a.unb64(c.b);
  eq("лист поля " + c.name, a.hex(a.fieldLeaf(c.name, a.unhex(c.salt), v)), c.leaf);
});

load("03-merkle").cases.forEach(function (c) {
  var leaves = c.leaves.map(a.unhex);
  eq("корень дерева n=" + c.n, a.hex(a.mth(leaves)), c.root);
  c.audit_paths.forEach(function (ap) {
    eq("путь n=" + c.n + " i=" + ap.index,
       a.hex(a.applyPath(leaves[ap.index], ap.path)), c.root);
  });
});

load("04-record").records.forEach(function (r) {
  eq("отпечаток содержимого seq=" + r.seq, a.hex(a.contentRoot(r.fields)), r.content_root);
});

load("05-chain").streams.forEach(function (s) {
  eq("нулевое звено " + s.stream_id, a.hex(a.genesis(s.stream_id)), s.genesis);
  var prev = a.unhex(s.genesis);
  s.links.forEach(function (l) {
    prev = a.link(prev, l.seq, a.unhex(l.content_root), l.ts);
    eq("звено " + s.stream_id + " seq=" + l.seq, a.hex(prev), l.link);
  });
});

var red = load("06-redaction");
eq("отпечаток после вычёркивания", a.hex(a.contentRoot(red.fields_after)),
   red.content_root_after);
eq("вычёркивание не изменило отпечаток", red.content_root_after, red.content_root_before);

var links = {};
load("05-chain").streams.forEach(function (s) {
  links[s.stream_id] = {};
  s.links.forEach(function (l) { links[s.stream_id][l.seq] = a.unhex(l.link); });
});
load("07-segment").cases.forEach(function (c) {
  var ls = [];
  for (var q = c.first_seq; q <= c.last_seq; q++) ls.push(a.segLeaf(links[c.stream_id][q]));
  eq("корень отрезка " + c.stream_id + " " + c.period_id, a.hex(a.mth(ls)), c.segment_root);
  eq("отметка отрезка " + c.stream_id + " " + c.period_id, a.hex(a.segCkpt(c)), c.checkpoint);
});

var d = load("08-day");
eq("суточный корень", a.hex(a.mth(d.segment_checkpoints.map(function (x) {
  return a.dayLeaf(a.unhex(x)); }))), d.day_root);
eq("суточная отметка", a.hex(a.dayCkpt(d)), d.day_checkpoint);

var inc = load("09-inclusion");
var rec = load("04-record").records.filter(function (r) { return r.seq === inc.seq; })[0];
eq("сквозной путь: отпечаток содержимого", a.hex(a.contentRoot(rec.fields)), inc.content_root);
eq("сквозной путь: лист отрезка", a.hex(a.segLeaf(a.unhex(inc.link))), inc.segment_leaf);
eq("сквозной путь: корень отрезка",
   a.hex(a.applyPath(a.segLeaf(a.unhex(inc.link)), inc.segment_path)), inc.segment_root);
eq("сквозной путь: суточный корень",
   a.hex(a.applyPath(a.dayLeaf(a.unhex(inc.segment_checkpoint)), inc.day_path)), inc.day_root);

reject("запись без полей", function () { a.contentRoot([]); });
reject("повтор имени поля", function () {
  a.contentRoot([{ name: "a", salt: "00".repeat(16), s: "1" },
                 { name: "a", salt: "01".repeat(16), s: "2" }]);
});
reject("пустое дерево", function () { a.mth([]); });
reject("соль не 16 байт", function () { a.fieldLeaf("a", a.unhex("0000"), a.utf8("v")); });
reject("пустое имя поля", function () { a.fieldLeaf("", a.unhex("00".repeat(16)), a.utf8("v")); });
reject("seq меньше 1", function () { a.link(new Uint8Array(32), 0, new Uint8Array(32), 0); });
reject("отрицательный varint", function () { a.varint(-1); });
reject("сторона не left/right", function () {
  a.applyPath(new Uint8Array(32), [{ side: "middle", h: "00".repeat(32) }]);
});
reject("вычеркнутое поле с солью", function () {
  a.contentRoot([{ name: "a", leaf: "00".repeat(32), salt: "00".repeat(16) }]);
});

/* --- настоящий ответ службы штампов времени ------------------------------ */
var FIX = path.join(__dirname, "..", "..", "spec", "fixtures", "rfc3161");
if (fs.existsSync(path.join(FIX, "meta.json"))) {
  var meta = JSON.parse(fs.readFileSync(path.join(FIX, "meta.json"), "utf8"));
  var tsr = new Uint8Array(fs.readFileSync(path.join(FIX, meta.file)));
  var target = a.unhex(meta.target);

  var r1 = a.verifyAnchorBlob("anchors/" + meta.file, tsr, target);
  eq("настоящий штамп относится к своей отметке", r1.status, "unverified");
  eq("тип пломбы определён", r1.type, "rfc3161");

  var r2 = a.verifyAnchorBlob("anchors/" + meta.file, tsr, new Uint8Array(32));
  eq("чужая отметка отвергнута", r2.status, "failed");

  console.log("фикстура службы штампов проверена (" + meta.tsa + ", " +
              meta.tsa_time + ")");
}

console.log("сошлось проверок: " + pass);
if (fail.length) {
  console.log("расхождений: " + fail.length + "\n");
  fail.forEach(function (f) { console.log("  " + f); });
  process.exit(1);
}
console.log("расхождений нет");
