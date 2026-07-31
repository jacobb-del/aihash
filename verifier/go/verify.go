package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Состояний не два: сегодняшняя запись ещё не запечатана, и бинарный
// «сходится / не сходится» на ней соврал бы.
//
// StatusUnverified и StatusOpen путать нельзя. Этот бинарь не разбирает CMS,
// поэтому подпись штампа RFC 3161 он не проверяет никогда — и объявлять из-за
// этого «не запечатано» значит занижать доказательство исправного журнала.
const (
	StatusSealed     = "sealed"
	StatusUnverified = "unverified"
	StatusOpen       = "open"
	StatusBroken     = "broken"
)

// Верификатор по определению обрабатывает файл, полученный от противоположной
// стороны. Без пределов присланный архив в мегабайт кладёт машину проверяющего:
// сжатие в тысячу раз — обычное дело. Законный пакет на порядки меньше.
const (
	MaxEntries    = 512
	MaxEntryBytes = 64 << 20
	MaxTotalBytes = 128 << 20
)

const (
	AnchorOK         = "ok"
	AnchorUnverified = "unverified"
	AnchorFailed     = "failed"
)

type Check struct {
	Label string `json:"label"`
	OK    bool   `json:"ok"`
}

type AnchorResult struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Date   string `json:"date,omitempty"`
	// Placed отвечает на вопрос «установлено ли, что пломба поставлена именно
	// на эту отметку» — отдельно от вопроса «удалось ли её проверить». Без
	// этого разделения «не проверена» сливает отсутствие пломбы с неоконченной
	// проверкой, а это разные ответы.
	//
	// Планка намеренно высокая: Placed ставится там, где принадлежность пломбы
	// отметке доказана, а не там, где в каталоге просто лежит подходяще
	// названный файл. Иначе любой файл, положенный в anchors/, смягчал бы
	// вердикт.
	Placed bool `json:"placed"`
}

// anchorRes — исход, из которого постановка пломбы на эту отметку не следует.
func anchorRes(typ, status, detail string) AnchorResult {
	return AnchorResult{Type: typ, Status: status, Detail: detail}
}

// anchorPlaced — исход, в котором принадлежность пломбы отметке доказана.
func anchorPlaced(typ, status, detail string) AnchorResult {
	return AnchorResult{Type: typ, Status: status, Detail: detail, Placed: true}
}

// dayStatus сводит пломбы одних суток в один из трёх исходов.
func dayStatus(anchors []AnchorResult) string {
	status := StatusOpen
	for _, a := range anchors {
		if a.Status == AnchorOK {
			return StatusSealed
		}
		if a.Status == AnchorUnverified && a.Placed {
			status = StatusUnverified
		}
	}
	return status
}

type Result struct {
	Status      string         `json:"status"`
	Kind        string         `json:"kind"`
	Path        string         `json:"path"`
	Checks      []Check        `json:"checks,omitempty"`
	Anchors     []AnchorResult `json:"anchors,omitempty"`
	Problems    []string       `json:"problems,omitempty"`
	RealmID     string         `json:"realm_id,omitempty"`
	StreamID    string         `json:"stream_id,omitempty"`
	PeriodID    string         `json:"period_id,omitempty"`
	Disclosed   []uint64       `json:"disclosed_of_total,omitempty"`
	Records     int            `json:"records,omitempty"`
	Redacted    int            `json:"redacted,omitempty"`
	LowerMS     uint64         `json:"lower_ms,omitempty"`
	LowerSource string         `json:"lower_source,omitempty"`
	SealedDays  []string       `json:"sealed_days,omitempty"`
	// UnverifiedDays — сутки, за которые пломба поставлена, но подтвердить её
	// здесь нечем. Отдельно от OpenDays: смешивать их значит занижать
	// доказательство исправного журнала.
	UnverifiedDays []string `json:"unverified_days,omitempty"`
	OpenDays       []string `json:"open_days,omitempty"`
}

func (r *Result) ok(label string, cond bool, detail string) bool {
	r.Checks = append(r.Checks, Check{label, cond})
	if !cond {
		if detail != "" {
			label += ": " + detail
		}
		r.Problems = append(r.Problems, label)
	}
	return cond
}

func (r *Result) fail(msg string) { r.Problems = append(r.Problems, msg) }

// --- пломбы -----------------------------------------------------------------

type feedEntry struct {
	Seq    uint64 `json:"seq"`
	Date   string `json:"date"`
	Target string `json:"target"`
	Prev   string `json:"prev"`
	Entry  string `json:"entry"`
}

// verifyFeed различает три исхода, и путать их нельзя:
//
//	нет записей за эти сутки       — пломба не поставлена (не подделка)
//	есть запись, отпечаток другой  — опубликовано другое: ПОДДЕЛКА
//	две записи с разными отметками — раздвоение журнала: ПОДДЕЛКА
//
// Вторая строка — единственное, ради чего лента и заводится. Считая её просто
// «не запечатано», мы пропустили бы противника, пересчитавшего журнал целиком.
func verifyFeed(data []byte, target []byte, date string) AnchorResult {
	prev := zero32
	var found *feedEntry
	var sameDate []feedEntry
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e feedEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return anchorRes("feed", AnchorFailed,
				fmt.Sprintf("feed entry %d does not parse", i+1))
		}
		if e.Prev != hexs(prev) {
			return anchorRes("feed", AnchorFailed,
				fmt.Sprintf("the feed is broken at entry %d", i+1))
		}
		tgt, err := unhex32(e.Target)
		if err != nil {
			return anchorRes("feed", AnchorFailed, err.Error())
		}
		want := h([]byte("aihash/feed/1"), lp([]byte(e.Date)), tgt, prev)
		if hexs(want) != e.Entry {
			return anchorRes("feed", AnchorFailed,
				fmt.Sprintf("fingerprint of feed entry %d does not match", i+1))
		}
		prev = want
		if date == "" || e.Date == date {
			sameDate = append(sameDate, e)
		}
		if bytes.Equal(tgt, target) {
			cp := e
			found = &cp
		}
	}

	distinct := map[string]bool{}
	for _, e := range sameDate {
		distinct[e.Target] = true
	}
	if len(distinct) > 1 {
		return anchorRes("feed", AnchorFailed, fmt.Sprintf(
			"%d different checkpoints published in the feed for these days — the journal was forked",
			len(distinct)))
	}
	if found != nil {
		return anchorPlaced("feed", AnchorOK, fmt.Sprintf(
			"entry %d in the feed; the strength of this seal depends on whether the feed is published outside",
			found.Seq))
	}
	if len(sameDate) > 0 {
		return anchorRes("feed", AnchorFailed, fmt.Sprintf(
			"a DIFFERENT checkpoint is published in the feed for these days (%s…) — "+
				"the journal does not match it", sameDate[0].Target[:16]))
	}
	// Лента цела, но этих суток в ней нет: пломба не была поставлена. Это
	// «пломбы нет», а не «пломба не подтверждена», поэтому Placed = false.
	return AnchorResult{Type: "feed", Status: AnchorUnverified, Placed: false,
		Detail: "the feed is intact but does not contain these days — the feed placed no seal"}
}

// verifyAnchorBlob проверяет пломбу по её байтам, без сети.
func verifyAnchorBlob(name string, data, target []byte, date string) AnchorResult {
	base := filepath.Base(name)
	switch {
	case base == "feed.jsonl":
		return verifyFeed(data, target, date)
	case strings.HasSuffix(base, ".rfc3161.tsr"):
		// Полная проверка требует разбора CMS и сертификата службы; здесь
		// проверяется только то, что штамп относится именно к этой отметке.
		if !bytes.Contains(data, target) {
			return anchorRes("rfc3161", AnchorFailed,
				"the timestamp was not placed on this daily checkpoint")
		}
		// Принадлежность штампа отметке доказана сырыми байтами выше: пломба
		// за эти сутки поставлена, вопрос только в подписи.
		return anchorPlaced("rfc3161", AnchorUnverified,
			"the timestamp covers this checkpoint, but the authority signature "+
				"was not verified — its certificate is needed: openssl ts -verify")
	case strings.HasSuffix(base, ".opentimestamps.ots"):
		// Разобрать .ots здесь нечем: что это пломба над нашей отметкой — не
		// установлено, поэтому и постановка пломбы не засчитывается.
		return anchorRes("opentimestamps", AnchorUnverified,
			"the opentimestamps client is required")
	default:
		// Файл в anchors/ есть, а что это — неизвестно. Ни принадлежность
		// отметке, ни сам факт постановки пломбы отсюда не следуют.
		return anchorRes(base, AnchorUnverified,
			"unknown seal type — skipped, and not counted")
	}
}

func beaconLowerBound(round uint64, source string) uint64 {
	if source != "drand:quicknet" {
		return 0
	}
	return (1692803367 + (round-1)*3) * 1000
}

// --- пакет доказательства ---------------------------------------------------

type Manifest struct {
	Format    string   `json:"format"`
	Hash      string   `json:"hash"`
	RealmID   string   `json:"realm_id"`
	StreamID  string   `json:"stream_id"`
	PeriodID  string   `json:"period_id"`
	Seqs      []uint64 `json:"seqs"`
	Created   uint64   `json:"created"`
	Beacon    *Beacon  `json:"beacon"`
	Disclosed []uint64 `json:"disclosed_of_total"`
}

type Beacon struct {
	Source string `json:"source"`
	Round  string `json:"round"`
	Seq    uint64 `json:"seq"`
}

type Record struct {
	V           int     `json:"v"`
	Seq         uint64  `json:"seq"`
	Ts          uint64  `json:"ts"`
	Fields      []Field `json:"fields"`
	ContentRoot string  `json:"content_root"`
	Link        string  `json:"link"`
}

type RecordProof struct {
	PrevLink    string     `json:"prev_link"`
	Link        string     `json:"link"`
	LeafIndex   int        `json:"leaf_index"`
	SegmentPath []PathStep `json:"segment_path"`
}

type Proofs struct {
	Records map[string]RecordProof `json:"records"`
	DayPath []PathStep             `json:"day_path"`
}

// safeName отвергает имена, выводящие за пределы архива. Мы ничего не
// распаковываем на диск, но имя попадает в вывод и в сообщения — принимать
// такое молча нельзя.
func safeName(name string) error {
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") {
		return fmt.Errorf("недопустимое имя в архиве: %q", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." || part == "." {
			return fmt.Errorf("имя в архиве выходит за его пределы: %q", name)
		}
	}
	return nil
}

func VerifyBundle(path string) *Result {
	r := &Result{Status: StatusBroken, Kind: "bundle", Path: path}

	zr, err := zip.OpenReader(path)
	if err != nil {
		r.fail("не читается как архив: " + err.Error())
		return r
	}
	defer zr.Close()

	if len(zr.File) > MaxEntries {
		r.fail(fmt.Sprintf("в архиве %d записей, предел %d", len(zr.File), MaxEntries))
		return r
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if err := safeName(f.Name); err != nil {
			r.fail(err.Error())
			return r
		}
		if f.UncompressedSize64 > MaxEntryBytes {
			r.fail(fmt.Sprintf("%s: заявлено %d байт, предел %d — архивная бомба",
				f.Name, f.UncompressedSize64, MaxEntryBytes))
			return r
		}
		rc, err := f.Open()
		if err != nil {
			r.fail("не читается " + f.Name)
			return r
		}
		// Заголовок архива может лгать о размере, поэтому чтение ограничено
		// независимо от заявленного.
		b, err := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
		rc.Close()
		if err != nil {
			r.fail("не читается " + f.Name)
			return r
		}
		if int64(len(b)) > MaxEntryBytes {
			r.fail(fmt.Sprintf("%s: распакованный размер превышает предел", f.Name))
			return r
		}
		total += int64(len(b))
		if total > MaxTotalBytes {
			r.fail(fmt.Sprintf("суммарный размер архива превышает %d байт", MaxTotalBytes))
			return r
		}
		files[f.Name] = b
	}

	need := func(name string, v any) bool {
		b, okf := files[name]
		if !okf {
			r.fail("в пакете нет " + name)
			return false
		}
		if err := json.Unmarshal(b, v); err != nil {
			r.fail(name + " не разбирается: " + err.Error())
			return false
		}
		return true
	}

	var manifest Manifest
	var proofs Proofs
	var segment Segment
	var day Day
	if !need("manifest.json", &manifest) || !need("proofs.json", &proofs) ||
		!need("segment.json", &segment) || !need("day.json", &day) {
		return r
	}
	recBytes, okf := files["records.jsonl"]
	if !okf {
		r.fail("в пакете нет records.jsonl")
		return r
	}
	var records []Record
	for i, line := range strings.Split(string(recBytes), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			r.fail(fmt.Sprintf("records.jsonl строка %d не разбирается", i+1))
			return r
		}
		if rec.Seq == 0 || len(rec.Fields) == 0 {
			r.fail(fmt.Sprintf("records.jsonl строка %d: нет seq или полей", i+1))
			return r
		}
		records = append(records, rec)
	}

	r.RealmID, r.StreamID, r.PeriodID = manifest.RealmID, manifest.StreamID, manifest.PeriodID
	r.Disclosed = manifest.Disclosed

	if !r.ok("format version", manifest.Format == FormatVersion, manifest.Format) {
		return r
	}
	if !r.ok("hash function", manifest.Hash == HashName, manifest.Hash) {
		return r
	}

	for _, rec := range records {
		p, okp := proofs.Records[strconv.FormatUint(rec.Seq, 10)]
		if !r.ok(fmt.Sprintf("record seq=%d: path in the bundle", rec.Seq), okp, "") {
			return r
		}
		croot, err := contentRoot(rec.Fields)
		if err != nil {
			r.ok(fmt.Sprintf("record seq=%d: fields", rec.Seq), false, err.Error())
			return r
		}
		prevLink, err := unhex32(p.PrevLink)
		if err != nil {
			r.ok(fmt.Sprintf("record seq=%d: previous link", rec.Seq), false, err.Error())
			return r
		}
		l, err := link(prevLink, rec.Seq, croot, rec.Ts)
		if err != nil {
			r.ok(fmt.Sprintf("record seq=%d: link", rec.Seq), false, err.Error())
			return r
		}
		if !r.ok(fmt.Sprintf("record seq=%d: content and link", rec.Seq),
			hexs(l) == p.Link, "") {
			return r
		}
		got, err := applyPath(segLeaf(l), p.SegmentPath)
		if err != nil {
			r.ok(fmt.Sprintf("record seq=%d: path to the segment root", rec.Seq), false, err.Error())
			return r
		}
		if !r.ok(fmt.Sprintf("record seq=%d: path to the segment root", rec.Seq),
			hexs(got) == segment.SegmentRoot, "") {
			return r
		}
	}

	ck, err := segment.computeCheckpoint()
	if err != nil {
		r.ok("segment checkpoint", false, err.Error())
		return r
	}
	if !r.ok("segment checkpoint", hexs(ck) == segment.Checkpoint, "") {
		return r
	}

	droot, err := applyPath(dayLeaf(ck), proofs.DayPath)
	if err != nil {
		r.ok("path to the daily root", false, err.Error())
		return r
	}
	if !r.ok("path to the daily root", hexs(droot) == day.DayRoot, "") {
		return r
	}

	dayRootBytes, err := unhex32(day.DayRoot)
	if err != nil {
		r.ok("суточный корень", false, err.Error())
		return r
	}
	dck, err := day.computeCheckpoint(dayRootBytes)
	if err != nil {
		r.ok("daily checkpoint", false, err.Error())
		return r
	}
	if !r.ok("daily checkpoint", hexs(dck) == day.DayCheckpoint, "") {
		return r
	}

	names := make([]string, 0, len(files))
	for n := range files {
		if strings.HasPrefix(n, "anchors/") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		res := verifyAnchorBlob(n, files[n], dck, day.Date)
		r.Anchors = append(r.Anchors, res)
		if res.Status == AnchorFailed {
			r.fail("seal " + res.Type + ": " + res.Detail)
		}
	}
	if len(r.Problems) > 0 {
		return r
	}

	if manifest.Beacon != nil {
		if round, err := strconv.ParseUint(manifest.Beacon.Round, 10, 64); err == nil {
			r.LowerMS = beaconLowerBound(round, manifest.Beacon.Source)
			r.LowerSource = manifest.Beacon.Source + " раунд " + manifest.Beacon.Round
		}
	}
	r.Records = len(records)
	r.Status = dayStatus(r.Anchors)
	return r
}

// --- журнал целиком ---------------------------------------------------------

type realmFile struct {
	Format  string `json:"format"`
	Hash    string `json:"hash"`
	RealmID string `json:"realm_id"`
}

func VerifyJournal(root string) *Result {
	r := &Result{Status: StatusBroken, Kind: "journal", Path: root}

	var realm realmFile
	if !readJSON(filepath.Join(root, "realm.json"), &realm, r) {
		r.fail("no realm.json — this directory is not an aihash journal")
		return r
	}
	r.RealmID = realm.RealmID
	if !r.ok("format version", realm.Format == FormatVersion, realm.Format) {
		return r
	}
	if !r.ok("hash function", realm.Hash == HashName, realm.Hash) {
		return r
	}

	streams, _ := listDirs(filepath.Join(root, "streams"))
	for _, s := range streams {
		// Звенья нужны только внутри проверки потока: удерживать их здесь
		// значило бы держать в памяти весь журнал без всякой пользы.
		verifyStream(root, s, r)
		if len(r.Problems) > 0 {
			return r
		}
	}

	dates, _ := listSuffixed(filepath.Join(root, "days"), ".day.json")
	sealedDates := map[string]bool{}
	prevExpected := zero32
	for _, date := range dates {
		var day Day
		if !readJSON(filepath.Join(root, "days", date+".day.json"), &day, r) {
			return r
		}
		sealedDates[date] = true
		if !verifyDay(root, realm.RealmID, date, day, prevExpected, r) {
			return r
		}
		prevExpected, _ = unhex32(day.DayCheckpoint)
	}

	openDays := map[string]bool{}
	for _, s := range streams {
		periods, _ := listSuffixed(filepath.Join(root, "streams", s, "segments"), ".jsonl")
		for _, p := range periods {
			if !sealedDates[p] {
				openDays[p] = true
			}
		}
	}
	for d := range openDays {
		r.OpenDays = append(r.OpenDays, d)
	}
	sort.Strings(r.OpenDays)

	if len(r.Problems) > 0 {
		return r
	}
	r.Status = StatusOpen
	if len(r.UnverifiedDays) > 0 {
		r.Status = StatusUnverified
	}
	if len(r.SealedDays) > 0 {
		r.Status = StatusSealed
	}
	return r
}

func verifyStream(root, streamID string, r *Result) map[uint64][]byte {
	out := map[uint64][]byte{}
	segDir := filepath.Join(root, "streams", streamID, "segments")
	periods, _ := listSuffixed(segDir, ".jsonl")
	prev := genesis(streamID)
	var expect uint64 = 1

	for _, period := range periods {
		linkBefore := prev
		data, err := os.ReadFile(filepath.Join(segDir, period+".jsonl"))
		if err != nil {
			r.fail("не читается отрезок " + period)
			return out
		}
		var recs []Record
		for i, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				r.fail(fmt.Sprintf("поток %s, отрезок %s, строка %d: не разбирается",
					streamID, period, i+1))
				return out
			}
			recs = append(recs, rec)
		}

		for _, rec := range recs {
			if rec.Seq != expect {
				r.fail(fmt.Sprintf("stream %s, segment %s: expected seq %d, found %d — gap in the chain",
					streamID, period, expect, rec.Seq))
				return out
			}
			croot, err := contentRoot(rec.Fields)
			if err != nil {
				r.fail(fmt.Sprintf("stream %s seq=%d: %s", streamID, rec.Seq, err))
				return out
			}
			prev, err = link(prev, rec.Seq, croot, rec.Ts)
			if err != nil {
				r.fail(fmt.Sprintf("stream %s seq=%d: %s", streamID, rec.Seq, err))
				return out
			}
			if hexs(prev) != rec.Link {
				r.fail(fmt.Sprintf("stream %s seq=%d: the link does not match the recorded one",
					streamID, rec.Seq))
				return out
			}
			out[rec.Seq] = prev
			expect++
			r.Records++
			for _, f := range rec.Fields {
				if f.Leaf != "" {
					r.Redacted++
				}
			}
		}

		ckPath := filepath.Join(segDir, period+".seg.json")
		if _, err := os.Stat(ckPath); err != nil || len(recs) == 0 {
			continue
		}
		var seg Segment
		if !readJSON(ckPath, &seg, r) {
			return out
		}
		segLinks := make([][]byte, 0, len(recs))
		for q := recs[0].Seq; q <= recs[len(recs)-1].Seq; q++ {
			segLinks = append(segLinks, out[q])
		}
		root2, err := segRoot(segLinks)
		if err != nil {
			r.fail(fmt.Sprintf("stream %s, segment %s: %s", streamID, period, err))
			return out
		}
		if hexs(root2) != seg.SegmentRoot {
			r.fail(fmt.Sprintf("stream %s, segment %s: корень отрезка не совпадает",
				streamID, period))
			return out
		}
		if seg.LinkBefore != hexs(linkBefore) {
			r.fail(fmt.Sprintf("stream %s, segment %s: не связан с предыдущим отрезком",
				streamID, period))
			return out
		}
		want, err := seg.computeCheckpoint()
		if err != nil || hexs(want) != seg.Checkpoint {
			r.fail(fmt.Sprintf("stream %s, segment %s: отметка отрезка не совпадает",
				streamID, period))
			return out
		}
	}
	return out
}

func verifyDay(root, realmID, date string, day Day, prevExpected []byte, r *Result) bool {
	ckpts := make([]string, 0, len(day.Streams))
	for _, s := range day.Streams {
		var seg Segment
		p := filepath.Join(root, "streams", s, "segments", date+".seg.json")
		if !readJSON(p, &seg, r) {
			r.fail(fmt.Sprintf("day %s: no segment checkpoint for stream %s", date, s))
			return false
		}
		ckpts = append(ckpts, seg.Checkpoint)
	}
	if strings.Join(ckpts, ",") != strings.Join(day.SegmentCheckpoints, ",") {
		r.fail(fmt.Sprintf("day %s: the list of segment checkpoints does not match", date))
		return false
	}
	if !sort.StringsAreSorted(day.Streams) {
		r.fail(fmt.Sprintf("day %s: streams are not sorted by stream_id", date))
		return false
	}
	root2, err := day.computeRoot()
	if err != nil || hexs(root2) != day.DayRoot {
		r.fail(fmt.Sprintf("day %s: the daily root does not match", date))
		return false
	}
	dck, err := day.computeCheckpoint(root2)
	if err != nil || hexs(dck) != day.DayCheckpoint {
		r.fail(fmt.Sprintf("day %s: the daily checkpoint does not match", date))
		return false
	}
	if day.PrevCheckpoint != hexs(prevExpected) {
		r.fail(fmt.Sprintf("day %s: not linked to the previous day", date))
		return false
	}

	anchorDir := filepath.Join(root, "anchors")
	var paths []string
	if entries, err := os.ReadDir(anchorDir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasPrefix(n, date+".") || n == "feed.jsonl" {
				paths = append(paths, filepath.Join(anchorDir, n))
			}
		}
	}
	sort.Strings(paths)
	var mine []AnchorResult
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		res := verifyAnchorBlob(p, data, dck, date)
		res.Date = date
		mine = append(mine, res)
		r.Anchors = append(r.Anchors, res)
		if res.Status == AnchorFailed {
			r.fail(fmt.Sprintf("day %s: seal %s does not match — %s", date, res.Type, res.Detail))
			return false
		}
	}
	switch dayStatus(mine) {
	case StatusSealed:
		r.SealedDays = append(r.SealedDays, date)
	case StatusUnverified:
		r.UnverifiedDays = append(r.UnverifiedDays, date)
	default:
		r.OpenDays = append(r.OpenDays, date)
	}
	return true
}

// --- вспомогательное --------------------------------------------------------

func hexs(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[2*i] = hexdig[c>>4]
		out[2*i+1] = hexdig[c&0x0f]
	}
	return string(out)
}

func readJSON(path string, v any, r *Result) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		r.fail(path + " не разбирается: " + err.Error())
		return false
	}
	return true
}

func listDirs(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func listSuffixed(path, suffix string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), suffix) {
			out = append(out, strings.TrimSuffix(e.Name(), suffix))
		}
	}
	sort.Strings(out)
	return out, nil
}
