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
	AnchorOK: "verified", AnchorUnverified: "not verified", AnchorFailed: "DOES NOT MATCH",
}

func printBroken(r *Result) {
	fmt.Println("DOES NOT MATCH")
	fmt.Println()
	for _, p := range r.Problems {
		fmt.Println("  " + p)
	}
	fmt.Println()
	fmt.Println("The previous content is not stored and cannot be recovered —")
	fmt.Println("only the fingerprint is kept. Which field was changed cannot be")
	fmt.Println("told from the fingerprint: it covers the record as a whole.")
}

func printBundle(r *Result) {
	if r.Status == StatusBroken {
		printBroken(r)
		return
	}
	fmt.Printf("Bundle %s\n", filepath.Base(r.Path))
	fmt.Printf("  journal %s, stream %s, segment %s\n", r.RealmID, r.StreamID, r.PeriodID)
	if len(r.Disclosed) == 2 {
		fmt.Printf("  %d of %d records in the segment disclosed\n", r.Disclosed[0], r.Disclosed[1])
	}
	fmt.Println()
	for _, c := range r.Checks {
		fmt.Println("  matches: " + c.Label)
	}
	fmt.Println()
	for _, a := range r.Anchors {
		fmt.Printf("  seal %s: %s — %s\n", a.Type, anchorWord[a.Status], a.Detail)
	}
	fmt.Println()
	switch r.Status {
	case StatusSealed:
		fmt.Println("Verdict: the content matches its fingerprint, the fingerprint is")
		fmt.Println("in the daily tree, and the daily checkpoint is sealed.")
	case StatusUnverified:
		fmt.Println("Verdict: the content matches its fingerprint and is in the daily tree.")
		fmt.Println("A seal was placed for these days but is not confirmed here — see")
		fmt.Println("its line above. Integrity is not proven until verifying the seal")
		fmt.Println("is finished; this is not the same as having no seal.")
	default:
		fmt.Println("Verdict: the content matches its fingerprint and is in the daily tree,")
		fmt.Println("but no seal was placed for these days. Integrity is not proven —")
		fmt.Println("only internal consistency is.")
	}
	if r.LowerMS != 0 {
		fmt.Printf("The record existed no earlier than %s (%s)\n", full(r.LowerMS), r.LowerSource)
		fmt.Println("and no later than the seal.")
	}
}

func printJournal(r *Result) {
	if r.Status == StatusBroken {
		printBroken(r)
		return
	}
	fmt.Printf("Journal %s: %d record(s)\n", r.RealmID, r.Records)
	if r.Redacted > 0 {
		fmt.Printf("  fields redacted: %d\n", r.Redacted)
	}
	fmt.Println("The chain matches end to end.")
	if len(r.SealedDays) > 0 {
		fmt.Printf("Days sealed: %d (%s)\n", len(r.SealedDays), strings.Join(r.SealedDays, ", "))
		printAnchorsOf(r, r.SealedDays)
	}
	if len(r.UnverifiedDays) > 0 {
		printUnconfirmed(r)
	}
	if len(r.OpenDays) > 0 {
		fmt.Printf("Days not sealed: %d (%s) — a seal is placed once a day\n",
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
	fmt.Printf("Seal present but not confirmed here: %d day(s) (%s)\n",
		len(r.UnverifiedDays), strings.Join(r.UnverifiedDays, ", "))
	printAnchorsOf(r, r.UnverifiedDays)
	fmt.Println("  This is not \"no seal\": a seal was placed for these days, " +
		"verifying it was not finished.")
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
	"rfc3161": "obtain the timestamp authority root certificate from the " +
		"authority itself (not from this bundle) and check the signature: " +
		"openssl ts -verify -digest <daily checkpoint> -in <file.tsr> -CAfile <cacert.pem>",
	"opentimestamps": "install the client and retry: " +
		"pip install opentimestamps-client",
}
