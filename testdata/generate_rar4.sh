#!/bin/bash
# generate_rar4.sh — Regenerates the RAR 1.5-4.x fixtures (rar4_*.rar).
#
# rar 7 removed the -ma4 switch, so these need rar 6.x or older, named by
# RAR4_RAR (e.g. RAR4_RAR=~/software/rar6/rar ./generate_rar4.sh). Without it
# the script says so and exits 0, so generate.sh can call it unconditionally.
#
# Runs on its own: regenerating these does not touch the RAR5 fixtures.

set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${RAR4_RAR:-}" ] || [ ! -x "$RAR4_RAR" ]; then
	echo "RAR4_RAR is not set to an executable rar 6.x; skipping rar4_*.rar"
	exit 0
fi

OUT=$(pwd)
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

echo -n "hello rardecode" >"$SRC/hello.txt"
echo -n "second file for testing" >"$SRC/second.txt"
echo -n "This is an archive comment for testing." >"$SRC/comment.txt"
mkdir -p "$SRC/subdir/nested"
echo -n "nested content" >"$SRC/subdir/nested/deep.txt"
echo -n "top level" >"$SRC/subdir/top.txt"
dd if=/dev/urandom of="$SRC/large.bin" bs=1024 count=8 2>/dev/null
echo -n "unicode name" >"$SRC/名前.txt"
for i in $(seq 1 60); do echo "line $i of a compressible text file"; done >"$SRC/text.txt"
for i in $(seq 1 60); do echo "row $i of a second compressible text file"; done >"$SRC/text2.txt"
ln -s hello.txt "$SRC/link_rel"
ln -s /etc/passwd "$SRC/link_abs"
ln -s ../../x "$SRC/link_up"

rar4() {
	local name=$1
	shift
	rm -f "$OUT/$name"
	(cd "$SRC" && "$RAR4_RAR" a -ma4 -idq "$@")
	echo "  $name"
}

echo "=== RAR 1.5-4.x fixtures ($("$RAR4_RAR" | sed -n 2p | cut -c1-12)) ==="
rm -f "$OUT"/rar4_store_multi.r[0-9][0-9]
rar4 rar4_store.rar -m0 "$OUT/rar4_store.rar" hello.txt second.txt
rar4 rar4_store_multi.rar -m0 -v4k -vn "$OUT/rar4_store_multi.rar" large.bin
rar4 rar4_dir.rar -m0 -r "$OUT/rar4_dir.rar" subdir
rar4 rar4_unicode.rar -m0 "$OUT/rar4_unicode.rar" 名前.txt
rar4 rar4_comment.rar -m0 -zcomment.txt "$OUT/rar4_comment.rar" hello.txt
rar4 rar4_rr.rar -m0 -rr3% "$OUT/rar4_rr.rar" hello.txt
# rar stores input it cannot shrink whatever -m says, and drops -s under -m0,
# so the compressed fixtures need compressible input and there is no solid
# stored one: a solid set exists only compressed.
rar4 rar4_lz.rar -m3 "$OUT/rar4_lz.rar" text.txt
rar4 rar4_solid_lz.rar -m3 -s "$OUT/rar4_solid_lz.rar" text.txt text2.txt
rar4 rar4_encrypted.rar -m0 -ptest "$OUT/rar4_encrypted.rar" hello.txt
rar4 rar4_hdrenc.rar -m0 -hptest "$OUT/rar4_hdrenc.rar" hello.txt
rar4 rar4_symlink.rar -m0 -ol "$OUT/rar4_symlink.rar" hello.txt link_rel link_abs link_up
