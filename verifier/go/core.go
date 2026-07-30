// Примитивы формата aihash/1.
//
// Нормативный источник — FORMAT.md. При расхождении прав документ.
// Сходимость с spec/vectors проверяется в core_test.go — теми же файлами, по
// которым проверяются Python и JavaScript.
//
// Только стандартная библиотека. Ни одной внешней зависимости: бинарь, который
// тянет чужой код, проверять доказательства не годится.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const (
	FormatVersion = "aihash/1"
	HashName      = "sha256"
	SaltLen       = 16
)

const (
	tagFieldLeaf = 0x01
	tagNode      = 0x02
	tagLink      = 0x03
	tagGenesis   = 0x04
	tagSegLeaf   = 0x05
	tagSegCkpt   = 0x06
	tagDayLeaf   = 0x07
	tagDayCkpt   = 0x08
)

var zero32 = make([]byte, 32)

// varint — LEB128 без знака.
func varint(n uint64) []byte {
	out := make([]byte, 0, 10)
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

func lp(b []byte) []byte { return append(varint(uint64(len(b))), b...) }

func h(parts ...[]byte) []byte {
	s := sha256.New()
	for _, p := range parts {
		s.Write(p)
	}
	return s.Sum(nil)
}

func tag(t byte) []byte { return []byte{t} }

func unhex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("не hex: %q", s)
	}
	return b, nil
}

func unhex32(s string) ([]byte, error) {
	b, err := unhex(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("отпечаток должен быть 32 байта, получено %d", len(b))
	}
	return b, nil
}

// --- лист поля --------------------------------------------------------------

func fieldLeaf(name string, salt, value []byte) ([]byte, error) {
	nb := []byte(name)
	if len(nb) < 1 || len(nb) > 255 {
		return nil, fmt.Errorf("длина имени поля вне 1..255: %q", name)
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("соль должна быть ровно %d байт", SaltLen)
	}
	return h(tag(tagFieldLeaf), lp(nb), lp(salt), lp(value)), nil
}

// --- дерево RFC 6962 --------------------------------------------------------

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// mth считает корень над УЖЕ готовыми листьями: повторного хеширования нет.
func mth(leaves [][]byte) ([]byte, error) {
	if len(leaves) == 0 {
		return nil, errors.New("пустое дерево запрещено")
	}
	if len(leaves) == 1 {
		return leaves[0], nil
	}
	k := split(len(leaves))
	l, err := mth(leaves[:k])
	if err != nil {
		return nil, err
	}
	r, err := mth(leaves[k:])
	if err != nil {
		return nil, err
	}
	return h(tag(tagNode), l, r), nil
}

// PathStep — шаг пути принадлежности. Сторона указана явно, а не выводится
// арифметикой по индексу: это самая частая ошибка при переносе на другой язык.
type PathStep struct {
	Side string `json:"side"`
	H    string `json:"h"`
}

func applyPath(leaf []byte, path []PathStep) ([]byte, error) {
	cur := leaf
	for _, s := range path {
		sib, err := unhex32(s.H)
		if err != nil {
			return nil, err
		}
		switch s.Side {
		case "right":
			cur = h(tag(tagNode), cur, sib)
		case "left":
			cur = h(tag(tagNode), sib, cur)
		default:
			return nil, fmt.Errorf("сторона должна быть left или right, получено %q", s.Side)
		}
	}
	return cur, nil
}

// --- запись -----------------------------------------------------------------

// Field — поле записи. Указатели у S и B нужны, чтобы отличить отсутствующее
// значение от пустого: пустое значение — законное значение.
type Field struct {
	Name     string          `json:"name"`
	Salt     string          `json:"salt,omitempty"`
	S        *string         `json:"s,omitempty"`
	B        *string         `json:"b,omitempty"`
	Leaf     string          `json:"leaf,omitempty"`
	Redacted *RedactionStamp `json:"redacted,omitempty"`
}

type RedactionStamp struct {
	At  uint64 `json:"at"`
	Seq uint64 `json:"seq"`
}

func (f Field) rawValue() ([]byte, error) {
	if f.S != nil && f.B != nil {
		return nil, fmt.Errorf("поле %q: s и b одновременно", f.Name)
	}
	if f.S != nil {
		return []byte(*f.S), nil
	}
	if f.B != nil {
		return b64decode(*f.B)
	}
	return nil, fmt.Errorf("поле %q: нет ни s, ни b", f.Name)
}

func (f Field) leaf() ([]byte, error) {
	if f.Leaf != "" {
		if f.Salt != "" || f.S != nil || f.B != nil {
			return nil, fmt.Errorf("вычеркнутое поле %q сохранило соль или значение", f.Name)
		}
		return unhex32(f.Leaf)
	}
	salt, err := unhex(f.Salt)
	if err != nil {
		return nil, err
	}
	val, err := f.rawValue()
	if err != nil {
		return nil, err
	}
	return fieldLeaf(f.Name, salt, val)
}

func contentRoot(fields []Field) ([]byte, error) {
	if len(fields) == 0 {
		return nil, errors.New("запись должна содержать хотя бы одно поле")
	}
	type item struct {
		name []byte
		leaf []byte
	}
	seen := make(map[string]bool, len(fields))
	items := make([]item, 0, len(fields))
	for _, f := range fields {
		if seen[f.Name] {
			return nil, fmt.Errorf("повтор имени поля: %s", f.Name)
		}
		seen[f.Name] = true
		l, err := f.leaf()
		if err != nil {
			return nil, err
		}
		items = append(items, item{[]byte(f.Name), l})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return bytes.Compare(items[i].name, items[j].name) < 0
	})
	leaves := make([][]byte, len(items))
	for i, it := range items {
		leaves[i] = it.leaf
	}
	return mth(leaves)
}

// --- цепь -------------------------------------------------------------------

func genesis(streamID string) []byte {
	return h(tag(tagGenesis), lp([]byte(streamID)), lp([]byte(FormatVersion)))
}

func link(prev []byte, seq uint64, croot []byte, ts uint64) ([]byte, error) {
	if seq < 1 {
		return nil, errors.New("seq начинается с 1")
	}
	if len(prev) != 32 || len(croot) != 32 {
		return nil, errors.New("отпечатки должны быть 32 байта")
	}
	return h(tag(tagLink), prev, varint(seq), croot, varint(ts)), nil
}

// --- отрезок и сутки --------------------------------------------------------

func segLeaf(l []byte) []byte { return h(tag(tagSegLeaf), l) }
func dayLeaf(c []byte) []byte { return h(tag(tagDayLeaf), c) }

func segRoot(links [][]byte) ([]byte, error) {
	leaves := make([][]byte, len(links))
	for i, l := range links {
		leaves[i] = segLeaf(l)
	}
	return mth(leaves)
}

type Segment struct {
	Format         string `json:"format"`
	StreamID       string `json:"stream_id"`
	PeriodID       string `json:"period_id"`
	FirstSeq       uint64 `json:"first_seq"`
	LastSeq        uint64 `json:"last_seq"`
	Count          uint64 `json:"count"`
	LinkBefore     string `json:"link_before"`
	LinkLast       string `json:"link_last"`
	SegmentRoot    string `json:"segment_root"`
	PrevCheckpoint string `json:"prev_checkpoint"`
	Checkpoint     string `json:"checkpoint"`
}

func (s Segment) computeCheckpoint() ([]byte, error) {
	if s.LastSeq-s.FirstSeq+1 != s.Count {
		return nil, errors.New("count не совпадает с диапазоном seq — пропуск в отрезке")
	}
	lb, err := unhex32(s.LinkBefore)
	if err != nil {
		return nil, err
	}
	ll, err := unhex32(s.LinkLast)
	if err != nil {
		return nil, err
	}
	root, err := unhex32(s.SegmentRoot)
	if err != nil {
		return nil, err
	}
	prev, err := unhex32(s.PrevCheckpoint)
	if err != nil {
		return nil, err
	}
	return h(tag(tagSegCkpt), lp([]byte(s.StreamID)), lp([]byte(s.PeriodID)),
		varint(s.FirstSeq), varint(s.LastSeq), varint(s.Count),
		lb, ll, root, prev), nil
}

type Day struct {
	Format             string   `json:"format"`
	RealmID            string   `json:"realm_id"`
	Date               string   `json:"date"`
	Streams            []string `json:"streams"`
	SegmentCheckpoints []string `json:"segment_checkpoints"`
	DayRoot            string   `json:"day_root"`
	PrevCheckpoint     string   `json:"prev_checkpoint"`
	DayCheckpoint      string   `json:"day_checkpoint"`
}

func (d Day) computeRoot() ([]byte, error) {
	if len(d.SegmentCheckpoints) == 0 {
		return nil, errors.New("сутки без потоков отметки не образуют")
	}
	leaves := make([][]byte, len(d.SegmentCheckpoints))
	for i, c := range d.SegmentCheckpoints {
		b, err := unhex32(c)
		if err != nil {
			return nil, err
		}
		leaves[i] = dayLeaf(b)
	}
	return mth(leaves)
}

func (d Day) computeCheckpoint(root []byte) ([]byte, error) {
	if len(d.Streams) == 0 {
		return nil, errors.New("сутки без потоков отметки не образуют")
	}
	prev, err := unhex32(d.PrevCheckpoint)
	if err != nil {
		return nil, err
	}
	return h(tag(tagDayCkpt), lp([]byte(d.RealmID)), lp([]byte(d.Date)),
		varint(uint64(len(d.Streams))), root, prev), nil
}

// --- base64 -----------------------------------------------------------------

const b64alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func b64decode(s string) ([]byte, error) {
	var acc, bits uint32
	out := make([]byte, 0, len(s)*3/4)
	for _, c := range s {
		if c == '=' || c == '\n' || c == '\r' || c == ' ' {
			continue
		}
		i := bytes.IndexByte([]byte(b64alpha), byte(c))
		if i < 0 {
			return nil, fmt.Errorf("недопустимый символ base64: %q", c)
		}
		acc = acc<<6 | uint32(i)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	return out, nil
}
