// aihash-verify — независимая проверка журнала и пакета доказательства.
//
//	aihash-verify ep.seal        проверить пакет
//	aihash-verify ./journal      проверить журнал целиком
//	aihash-verify -json ep.seal  машиночитаемый вывод для CI
//
// Ни сети, ни внешних зависимостей, ни обращения к тому, кто выдал файл.
//
// Коды возврата:
//
//	0 — сходится и запечатано: содержимое доказано
//	3 — сходится, но пломба не поставлена либо не подтверждена здесь: НЕ доказано
//	1 — не сходится
//	2 — файл не прочитан
//
// Отдельный код для «не подтверждено» существует потому, что автоматическая
// проверка смотрит на код возврата. Ноль на пакете без пломбы означал бы
// «всё в порядке» там, где не доказано ничего. Код 3 объединяет два разных
// случая намеренно, но словами их различать обязательно.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var version = "0.1.0"

func main() {
	asJSON := flag.Bool("json", false, "машиночитаемый вывод")
	showVer := flag.Bool("version", false, "версия")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"aihash-verify %s — проверка формата %s\n\n"+
				"использование:\n  aihash-verify [-json] <файл.seal | каталог журнала>\n\n",
			version, FormatVersion)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("aihash-verify %s (формат %s)\n", version, FormatVersion)
		return
	}
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	path := flag.Arg(0)
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "не прочитан: "+err.Error())
		os.Exit(2)
	}

	var r *Result
	if info.IsDir() {
		r = VerifyJournal(path)
	} else {
		r = VerifyBundle(path)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else if r.Kind == "bundle" {
		printBundle(r)
	} else {
		printJournal(r)
	}

	switch {
	case r.Status == StatusBroken:
		os.Exit(1)
	case r.Kind == "bundle" && r.Status != StatusSealed:
		os.Exit(3)
	}
}

func full(ms uint64) string {
	if ms == 0 {
		return "—"
	}
	return time.UnixMilli(int64(ms)).UTC().Format("02.01.2006 15:04 UTC")
}

var anchorWord = map[string]string{
	AnchorOK: "проверена", AnchorUnverified: "не проверена", AnchorFailed: "НЕ СХОДИТСЯ",
}

func printBroken(r *Result) {
	fmt.Println("НЕ СХОДИТСЯ")
	fmt.Println()
	for _, p := range r.Problems {
		fmt.Println("  " + p)
	}
	fmt.Println()
	fmt.Println("Прежнее содержимое не сохранено и восстановлению не подлежит —")
	fmt.Println("хранится только отпечаток. Определить, какое именно поле изменено,")
	fmt.Println("по отпечатку невозможно: он считается по записи целиком.")
}

func printBundle(r *Result) {
	if r.Status == StatusBroken {
		printBroken(r)
		return
	}
	fmt.Printf("Пакет %s\n", filepath.Base(r.Path))
	fmt.Printf("  журнал %s, поток %s, отрезок %s\n", r.RealmID, r.StreamID, r.PeriodID)
	if len(r.Disclosed) == 2 {
		fmt.Printf("  раскрыто записей %d из %d в отрезке\n", r.Disclosed[0], r.Disclosed[1])
	}
	fmt.Println()
	for _, c := range r.Checks {
		fmt.Println("  сходится: " + c.Label)
	}
	fmt.Println()
	for _, a := range r.Anchors {
		fmt.Printf("  пломба %s: %s — %s\n", a.Type, anchorWord[a.Status], a.Detail)
	}
	fmt.Println()
	switch r.Status {
	case StatusSealed:
		fmt.Println("Вывод: содержимое совпадает с отпечатком, отпечаток входит в")
		fmt.Println("суточное дерево, суточная отметка запечатана.")
	case StatusUnverified:
		fmt.Println("Вывод: содержимое совпадает с отпечатком и входит в суточное дерево.")
		fmt.Println("Пломба за эти сутки поставлена, но здесь не подтверждена — см. её")
		fmt.Println("строку выше. Неизменность не доказана, пока проверка пломбы не")
		fmt.Println("доведена до конца; отсутствием пломбы это не является.")
	default:
		fmt.Println("Вывод: содержимое совпадает с отпечатком и входит в суточное дерево,")
		fmt.Println("но пломба за эти сутки не поставлена. Неизменность")
		fmt.Println("не доказана — доказана только внутренняя согласованность.")
	}
	if r.LowerMS != 0 {
		fmt.Printf("Запись существовала не ранее %s (%s)\n", full(r.LowerMS), r.LowerSource)
		fmt.Println("и не позднее постановки пломбы.")
	}
}

func printJournal(r *Result) {
	if r.Status == StatusBroken {
		printBroken(r)
		return
	}
	fmt.Printf("Журнал %s: записей %d\n", r.RealmID, r.Records)
	if r.Redacted > 0 {
		fmt.Printf("  вычеркнуто полей: %d\n", r.Redacted)
	}
	fmt.Println("Цепь сходится на всём протяжении.")
	if len(r.SealedDays) > 0 {
		fmt.Printf("Запечатано суток: %d (%s)\n", len(r.SealedDays), strings.Join(r.SealedDays, ", "))
		printAnchorsOf(r, r.SealedDays)
	}
	if len(r.UnverifiedDays) > 0 {
		printUnconfirmed(r)
	}
	if len(r.OpenDays) > 0 {
		fmt.Printf("Не запечатано суток: %d (%s) — пломба ставится раз в сутки\n",
			len(r.OpenDays), strings.Join(r.OpenDays, ", "))
	}
}

func printAnchorsOf(r *Result, dates []string) {
	want := map[string]bool{}
	for _, d := range dates {
		want[d] = true
	}
	for _, a := range r.Anchors {
		if a.Status != AnchorFailed && want[a.Date] {
			fmt.Printf("  %s: %s — %s\n", a.Date, a.Type, a.Detail)
		}
	}
}

// Пломба стоит, но подтвердить её нечем. Отдельный случай, а не разновидность
// «не запечатано»: для штампа RFC 3161 это ЕДИНСТВЕННЫЙ достижимый здесь исход
// — разбора CMS в этом бинаре нет и не будет, — и объявлять из-за этого журнал
// незапечатанным значит занижать доказательство за его владельца.
func printUnconfirmed(r *Result) {
	fmt.Printf("Пломба стоит, но здесь не подтверждена: суток %d (%s)\n",
		len(r.UnverifiedDays), strings.Join(r.UnverifiedDays, ", "))
	printAnchorsOf(r, r.UnverifiedDays)
	fmt.Println("  Это не «пломбы нет»: пломба за эти сутки поставлена, " +
		"не доведена до конца её проверка.")
	seen := map[string]bool{}
	unverified := map[string]bool{}
	for _, d := range r.UnverifiedDays {
		unverified[d] = true
	}
	for _, a := range r.Anchors {
		if !unverified[a.Date] || a.Status != AnchorUnverified || !a.Placed || seen[a.Type] {
			continue
		}
		seen[a.Type] = true
		if how := howToConfirm[a.Type]; how != "" {
			fmt.Printf("  %s: %s\n", a.Type, how)
		}
	}
}

// Чего не хватает и где это взять. Без второй половины сообщение бесполезно:
// получатель узнаёт, что проверка неполна, и не узнаёт, как её достроить.
var howToConfirm = map[string]string{
	"rfc3161": "возьмите корневой сертификат службы штампов у неё самой " +
		"(не из этого пакета) и сверьте подпись: " +
		"openssl ts -verify -digest <суточная отметка> -in <файл.tsr> -CAfile <cacert.pem>",
	"opentimestamps": "поставьте клиент и повторите: " +
		"pip install opentimestamps-client",
}
