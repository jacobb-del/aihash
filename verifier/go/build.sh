#!/bin/sh
# Сборка бинарей под все платформы, где может оказаться оппонент.
#
#   sh verifier/go/build.sh          только текущая платформа
#   sh verifier/go/build.sh --all    все
#
# CGO выключен: бинарь не должен зависеть ни от чего на машине проверяющего.
# На Linux это даёт полностью статический файл. На macOS Go всегда линкует
# libSystem — там «статический» означает «без сторонних зависимостей», а не
# «без единой динамической библиотеки»; обойти это нельзя, у macOS нет
# устойчивого ABI системных вызовов.
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
OUT="$DIR/../dist"
mkdir -p "$OUT"

build() {
    goos=$1 goarch=$2 ext=${3:-}
    name="aihash-verify-$goos-$goarch$ext"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -C "$DIR" -trimpath -ldflags="-s -w" -o "$OUT/$name" .
    printf '  %-34s %s\n' "$name" "$(du -h "$OUT/$name" | cut -f1)"
}

echo "собираю:"
if [ "${1:-}" = "--all" ]; then
    build darwin arm64
    build darwin amd64
    build linux amd64
    build linux arm64
    build windows amd64 .exe
else
    build "$(go env GOOS)" "$(go env GOARCH)"
fi

CGO_ENABLED=0 go build -C "$DIR" -trimpath -ldflags="-s -w" -o "$OUT/aihash-verify" .
echo "  aihash-verify                      (текущая платформа)"

echo
echo "отпечатки — их и сверяет получатель, если файл пришёл от стороны спора:"
cd "$OUT" && shasum -a 256 aihash-verify* verify.html 2>/dev/null | sed 's/^/  /'
