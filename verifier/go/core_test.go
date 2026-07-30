// Бинарь обязан сходиться с векторами этапа 0 побайтово — теми же файлами,
// по которым проверяются Python и JavaScript. Это единственное, что не даёт
// трём реализациям разъехаться.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const vectorsDir = "../../spec/vectors"

func load(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir, name+".json"))
	if err != nil {
		t.Fatalf("вектор %s не прочитан: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("вектор %s не разобран: %v", name, err)
	}
}

func TestVarint(t *testing.T) {
	var v struct {
		Cases []struct {
			Value uint64 `json:"value"`
			Hex   string `json:"hex"`
		} `json:"cases"`
	}
	load(t, "01-varint", &v)
	for _, c := range v.Cases {
		if got := hexs(varint(c.Value)); got != c.Hex {
			t.Errorf("varint(%d) = %s, ожидалось %s", c.Value, got, c.Hex)
		}
	}
}

func TestFieldLeaf(t *testing.T) {
	var raw struct {
		Cases []struct {
			Name string  `json:"name"`
			Salt string  `json:"salt"`
			S    *string `json:"s"`
			B    *string `json:"b"`
			Leaf string  `json:"leaf"`
		} `json:"cases"`
	}
	load(t, "02-field-leaf", &raw)
	for _, c := range raw.Cases {
		f := Field{Name: c.Name, Salt: c.Salt, S: c.S, B: c.B}
		val, err := f.rawValue()
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		salt, _ := unhex(c.Salt)
		got, err := fieldLeaf(c.Name, salt, val)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if hexs(got) != c.Leaf {
			t.Errorf("лист поля %s = %s, ожидалось %s", c.Name, hexs(got), c.Leaf)
		}
	}
}

func TestMerkleAndPaths(t *testing.T) {
	var v struct {
		Cases []struct {
			N          int      `json:"n"`
			Leaves     []string `json:"leaves"`
			Root       string   `json:"root"`
			AuditPaths []struct {
				Index int        `json:"index"`
				Path  []PathStep `json:"path"`
			} `json:"audit_paths"`
		} `json:"cases"`
	}
	load(t, "03-merkle", &v)
	for _, c := range v.Cases {
		leaves := make([][]byte, len(c.Leaves))
		for i, x := range c.Leaves {
			leaves[i], _ = unhex32(x)
		}
		root, err := mth(leaves)
		if err != nil {
			t.Fatalf("n=%d: %v", c.N, err)
		}
		if hexs(root) != c.Root {
			t.Errorf("корень n=%d = %s, ожидалось %s", c.N, hexs(root), c.Root)
		}
		for _, ap := range c.AuditPaths {
			got, err := applyPath(leaves[ap.Index], ap.Path)
			if err != nil {
				t.Fatalf("путь n=%d i=%d: %v", c.N, ap.Index, err)
			}
			if hexs(got) != c.Root {
				t.Errorf("путь n=%d i=%d не привёл к корню", c.N, ap.Index)
			}
		}
	}
}

func TestRecords(t *testing.T) {
	var v struct {
		Records []Record `json:"records"`
	}
	load(t, "04-record", &v)
	for _, r := range v.Records {
		got, err := contentRoot(r.Fields)
		if err != nil {
			t.Fatalf("seq=%d: %v", r.Seq, err)
		}
		if hexs(got) != r.ContentRoot {
			t.Errorf("отпечаток seq=%d = %s, ожидалось %s", r.Seq, hexs(got), r.ContentRoot)
		}
	}
}

func TestChain(t *testing.T) {
	var v struct {
		Streams []struct {
			StreamID string `json:"stream_id"`
			Genesis  string `json:"genesis"`
			Links    []struct {
				Seq         uint64 `json:"seq"`
				Ts          uint64 `json:"ts"`
				ContentRoot string `json:"content_root"`
				Link        string `json:"link"`
			} `json:"links"`
		} `json:"streams"`
	}
	load(t, "05-chain", &v)
	for _, s := range v.Streams {
		if hexs(genesis(s.StreamID)) != s.Genesis {
			t.Errorf("нулевое звено %s не совпадает", s.StreamID)
		}
		prev, _ := unhex32(s.Genesis)
		for _, l := range s.Links {
			croot, _ := unhex32(l.ContentRoot)
			var err error
			prev, err = link(prev, l.Seq, croot, l.Ts)
			if err != nil {
				t.Fatalf("%s seq=%d: %v", s.StreamID, l.Seq, err)
			}
			if hexs(prev) != l.Link {
				t.Errorf("звено %s seq=%d не совпадает", s.StreamID, l.Seq)
			}
		}
	}
}

func TestRedactionPreservesContentRoot(t *testing.T) {
	var v struct {
		Before      string  `json:"content_root_before"`
		After       string  `json:"content_root_after"`
		FieldsAfter []Field `json:"fields_after"`
	}
	load(t, "06-redaction", &v)
	got, err := contentRoot(v.FieldsAfter)
	if err != nil {
		t.Fatal(err)
	}
	if hexs(got) != v.After || v.After != v.Before {
		t.Fatalf("вычёркивание изменило отпечаток записи: %s -> %s", v.Before, hexs(got))
	}
	for _, f := range v.FieldsAfter {
		if f.Leaf != "" && (f.Salt != "" || f.S != nil || f.B != nil) {
			t.Errorf("вычеркнутое поле %s сохранило соль или значение", f.Name)
		}
	}
}

func TestSegments(t *testing.T) {
	var chain struct {
		Streams []struct {
			StreamID string `json:"stream_id"`
			Links    []struct {
				Seq  uint64 `json:"seq"`
				Link string `json:"link"`
			} `json:"links"`
		} `json:"streams"`
	}
	load(t, "05-chain", &chain)
	links := map[string]map[uint64][]byte{}
	for _, s := range chain.Streams {
		links[s.StreamID] = map[uint64][]byte{}
		for _, l := range s.Links {
			links[s.StreamID][l.Seq], _ = unhex32(l.Link)
		}
	}

	var v struct {
		Cases []Segment `json:"cases"`
	}
	load(t, "07-segment", &v)
	for _, c := range v.Cases {
		var ls [][]byte
		for q := c.FirstSeq; q <= c.LastSeq; q++ {
			ls = append(ls, links[c.StreamID][q])
		}
		root, err := segRoot(ls)
		if err != nil {
			t.Fatal(err)
		}
		if hexs(root) != c.SegmentRoot {
			t.Errorf("корень отрезка %s %s не совпадает", c.StreamID, c.PeriodID)
		}
		ck, err := c.computeCheckpoint()
		if err != nil {
			t.Fatal(err)
		}
		if hexs(ck) != c.Checkpoint {
			t.Errorf("отметка отрезка %s %s не совпадает", c.StreamID, c.PeriodID)
		}
	}
}

func TestDay(t *testing.T) {
	var d Day
	load(t, "08-day", &d)
	root, err := d.computeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if hexs(root) != d.DayRoot {
		t.Fatalf("суточный корень не совпадает")
	}
	ck, err := d.computeCheckpoint(root)
	if err != nil {
		t.Fatal(err)
	}
	if hexs(ck) != d.DayCheckpoint {
		t.Fatalf("суточная отметка не совпадает")
	}
}

func TestInclusionEndToEnd(t *testing.T) {
	var inc struct {
		Seq               uint64     `json:"seq"`
		ContentRoot       string     `json:"content_root"`
		Link              string     `json:"link"`
		SegmentLeaf       string     `json:"segment_leaf"`
		SegmentPath       []PathStep `json:"segment_path"`
		SegmentRoot       string     `json:"segment_root"`
		SegmentCheckpoint string     `json:"segment_checkpoint"`
		DayLeaf           string     `json:"day_leaf"`
		DayPath           []PathStep `json:"day_path"`
		DayRoot           string     `json:"day_root"`
	}
	load(t, "09-inclusion", &inc)
	var recs struct {
		Records []Record `json:"records"`
	}
	load(t, "04-record", &recs)

	for _, r := range recs.Records {
		if r.Seq != inc.Seq {
			continue
		}
		croot, err := contentRoot(r.Fields)
		if err != nil || hexs(croot) != inc.ContentRoot {
			t.Fatalf("отпечаток содержимого не совпадает")
		}
	}
	l, _ := unhex32(inc.Link)
	if hexs(segLeaf(l)) != inc.SegmentLeaf {
		t.Fatalf("лист отрезка не совпадает")
	}
	got, err := applyPath(segLeaf(l), inc.SegmentPath)
	if err != nil || hexs(got) != inc.SegmentRoot {
		t.Fatalf("путь до корня отрезка не сходится")
	}
	sc, _ := unhex32(inc.SegmentCheckpoint)
	got, err = applyPath(dayLeaf(sc), inc.DayPath)
	if err != nil || hexs(got) != inc.DayRoot {
		t.Fatalf("путь до суточного корня не сходится")
	}
}

// Реализация, принимающая эти случаи, не соответствует спецификации, даже если
// все положительные векторы сошлись.
func TestMustBeRejected(t *testing.T) {
	s := func(x string) *string { return &x }
	cases := []struct {
		label string
		fn    func() error
	}{
		{"запись без полей", func() error { _, e := contentRoot(nil); return e }},
		{"повтор имени поля", func() error {
			_, e := contentRoot([]Field{
				{Name: "a", Salt: "00000000000000000000000000000000", S: s("1")},
				{Name: "a", Salt: "01010101010101010101010101010101", S: s("2")}})
			return e
		}},
		{"пустое дерево", func() error { _, e := mth(nil); return e }},
		{"соль не 16 байт", func() error {
			_, e := fieldLeaf("a", make([]byte, 8), []byte("v"))
			return e
		}},
		{"пустое имя поля", func() error {
			_, e := fieldLeaf("", make([]byte, 16), []byte("v"))
			return e
		}},
		{"seq меньше 1", func() error { _, e := link(zero32, 0, zero32, 0); return e }},
		{"сторона не left/right", func() error {
			_, e := applyPath(zero32, []PathStep{{Side: "middle", H: hexs(zero32)}})
			return e
		}},
		{"count не совпадает с диапазоном", func() error {
			seg := Segment{StreamID: "s", PeriodID: "2026-03-12", FirstSeq: 1,
				LastSeq: 5, Count: 4, LinkBefore: hexs(zero32), LinkLast: hexs(zero32),
				SegmentRoot: hexs(zero32), PrevCheckpoint: hexs(zero32)}
			_, e := seg.computeCheckpoint()
			return e
		}},
		{"вычеркнутое поле с солью", func() error {
			_, e := contentRoot([]Field{{Name: "a", Leaf: hexs(zero32),
				Salt: "00000000000000000000000000000000"}})
			return e
		}},
		{"s и b одновременно", func() error {
			f := Field{Name: "a", Salt: hexs(make([]byte, 16)), S: s("x"), B: s("eA==")}
			_, e := f.leaf()
			return e
		}},
	}
	for _, c := range cases {
		if err := c.fn(); err == nil {
			t.Errorf("должно было быть отвергнуто: %s", c.label)
		}
	}
	fmt.Fprintln(os.Stderr, "отрицательных случаев проверено:", len(cases))
}
