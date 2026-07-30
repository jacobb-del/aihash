// Настоящий ответ службы штампов времени.
//
// Фикстура получена живым прогоном против freetsa.org. Она закрывает ошибку,
// из-за которой верификатор мог ложно обвинить исправный штамп: отпечаток
// лежит в DER как есть, и проверять надо сырые байты, а не текстовый дамп.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const fixturesDir = "../../spec/fixtures/rfc3161"

func fixture(t *testing.T) (data, target []byte, meta map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "meta.json"))
	if err != nil {
		t.Skip("фикстура недоступна")
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("meta.json не разобран: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(fixturesDir, meta["file"]))
	if err != nil {
		t.Fatalf("ответ службы не прочитан: %v", err)
	}
	target, err = unhex32(meta["target"])
	if err != nil {
		t.Fatalf("отметка не разобрана: %v", err)
	}
	return
}

func TestRealStampBelongsToItsTarget(t *testing.T) {
	data, target, meta := fixture(t)
	res := verifyAnchorBlob(meta["file"], data, target, "")
	if res.Status == AnchorFailed {
		t.Fatalf("исправный штамп объявлен несходящимся: %s", res.Detail)
	}
	if res.Type != "rfc3161" {
		t.Fatalf("тип пломбы определён как %q", res.Type)
	}
}

func TestWrongTargetIsRejected(t *testing.T) {
	data, _, meta := fixture(t)
	res := verifyAnchorBlob(meta["file"], data, make([]byte, 32), "")
	if res.Status != AnchorFailed {
		t.Fatalf("чужая отметка принята: %s", res.Detail)
	}
}

func TestSignatureIsNotClaimedVerifiedWithoutCertificate(t *testing.T) {
	// Бинарь не разбирает CMS: он обязан назвать подпись непроверенной,
	// а не выдать её за подтверждённую.
	data, target, meta := fixture(t)
	res := verifyAnchorBlob(meta["file"], data, target, "")
	if res.Status != AnchorUnverified {
		t.Fatalf("ожидалось «не проверена», получено %q", res.Status)
	}
}

// Отсутствие суточной отметки в ленте — не подделка, а отсутствие пломбы.
// Обвинение за чужой отказ — худший отказ, какой может выдать верификатор.
func TestFeedWithoutTheDayIsUnverifiedNotFailed(t *testing.T) {
	target := make([]byte, 32)
	target[0] = 0xAA
	other := make([]byte, 32)
	other[0] = 0xBB
	entry := h([]byte("aihash/feed/1"), lp([]byte("2026-07-28")), other, zero32)
	line := `{"seq":1,"date":"2026-07-28","target":"` + hexs(other) +
		`","prev":"` + hexs(zero32) + `","entry":"` + hexs(entry) + `"}`

	// Записи за ДРУГУЮ дату — этих суток в ленте нет вовсе.
	res := verifyFeed([]byte(line+"\n"), target, "2026-07-29")
	if res.Status != AnchorUnverified {
		t.Fatalf("целая лента без этих суток объявлена %q, ожидалось %q: %s",
			res.Status, AnchorUnverified, res.Detail)
	}

	broken := `{"seq":1,"date":"2026-07-28","target":"` + hexs(other) +
		`","prev":"` + hexs(target) + `","entry":"` + hexs(entry) + `"}`
	if verifyFeed([]byte(broken+"\n"), target, "").Status != AnchorFailed {
		t.Fatal("порванная лента обязана оставаться подделкой")
	}
}
