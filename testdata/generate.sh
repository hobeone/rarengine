#!/bin/bash
# generate.sh — Regenerates all RAR test fixtures from scratch.
#
# Requirements: rar (v5+), ln -s, python3, gcc (for the x86 filter fixture)
#
# The .rar files are the canonical test fixtures (checked into git).
# This script documents how they were created and can regenerate them
# if needed (note: output may not be byte-identical across rar versions).

set -euo pipefail

cd "$(dirname "$0")"

# Create a temp directory for source files
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Known test content — small, deterministic
echo -n "hello rardecode" > "$TMPDIR/hello.txt"
echo -n "second file for testing" > "$TMPDIR/second.txt"

# Create a directory structure for directory tests
mkdir -p "$TMPDIR/subdir/nested"
echo -n "nested content" > "$TMPDIR/subdir/nested/deep.txt"
echo -n "top level" > "$TMPDIR/subdir/top.txt"

# Create a larger file for multi-volume splitting
dd if=/dev/urandom of="$TMPDIR/large.bin" bs=1024 count=8 2>/dev/null

# Comment file
echo -n "This is an archive comment for testing." > "$TMPDIR/comment.txt"

echo "=== Generating RAR5 test fixtures ==="

# 1. RAR5, no compression (store), CRC32
rar a -m0 -ma5 -ep rar5_store.rar "$TMPDIR/hello.txt"
echo "  rar5_store.rar"

# 2. RAR5, compression method 3, CRC32
rar a -m3 -ma5 -ep rar5_compress.rar "$TMPDIR/hello.txt" "$TMPDIR/second.txt"
echo "  rar5_compress.rar"

# 3. RAR5, solid archive
rar a -m3 -ma5 -s -ep rar5_solid.rar "$TMPDIR/hello.txt" "$TMPDIR/second.txt"
echo "  rar5_solid.rar"

# 3b. RAR5, solid archive — realistic ~5MB single-file payload for BenchmarkDecompress_Solid.
# The tiny rar5_solid.rar above is dominated by per-archive setup; this fixture
# exercises the actual decode hot path (LZ77 + Huffman) at sensible scale.
# Source is mixed pseudo-English text + deterministic PRNG noise (no /dev/urandom)
# so regeneration produces archives of similar size and compressibility.
python3 - "$TMPDIR/solid_bench.bin" <<'PY'
import random, sys
random.seed(42)
words = ['the','quick','brown','fox','jumps','over','lazy','dog','rar','engine',
         'huffman','decode','window','solid','stream','buffer','offset','length',
         'symbol','table']
with open(sys.argv[1], 'wb') as out:
    size = 0
    while size < 5 * 1024 * 1024:
        if random.random() < 0.8:
            b = (' '.join(random.choices(words, k=20)) + '\n').encode()
        else:
            b = bytes(random.getrandbits(8) for _ in range(64))
        out.write(b); size += len(b)
PY
rar a -m3 -ma5 -s -ep rar5_solid_bench.rar "$TMPDIR/solid_bench.bin"
echo "  rar5_solid_bench.rar"

# 4. RAR5, directories
rar a -ma5 -r rar5_directory.rar "$TMPDIR/subdir/"
echo "  rar5_directory.rar"

# 5. RAR5, BLAKE2sp hash
rar a -ma5 -htb -ep rar5_blake2.rar "$TMPDIR/hello.txt"
echo "  rar5_blake2.rar"

# 6. RAR5, file encryption (password: "test")
rar a -ma5 -p'test' -ep rar5_encrypted.rar "$TMPDIR/hello.txt"
echo "  rar5_encrypted.rar"

# 7. RAR5, header encryption (password: "test")
rar a -ma5 -hp'test' -ep rar5_encrypted_header.rar "$TMPDIR/hello.txt"
echo "  rar5_encrypted_header.rar"

# 8. RAR5, all timestamps
rar a -ma5 -tsm -tsc -tsa -ep rar5_times.rar "$TMPDIR/hello.txt"
echo "  rar5_times.rar"

# 9. RAR5, symlink
ln -sf hello.txt "$TMPDIR/link.txt"
rar a -ma5 -ol rar5_symlink.rar "$TMPDIR/link.txt"
echo "  rar5_symlink.rar"

# 10. RAR5, unix owner
rar a -ma5 -ow -ep rar5_unix_owner.rar "$TMPDIR/hello.txt"
echo "  rar5_unix_owner.rar"

# 11. RAR5, multi-volume (1KB volumes)
rar a -ma5 -v1k -ep rar5_multi.rar "$TMPDIR/large.bin"
echo "  rar5_multi.part*.rar"

# 11b. RAR5, encrypted AND multi-volume, in both methods.
#
# The only fixtures where decryption has to survive a volume advance: a file's
# ciphertext is one continuous CBC stream, and 1 KB volumes cut it mid-block
# (the compressed parts come out 765, 764 and 599 bytes and the stored ones
# 765, 764 and 551 -- none of them a whole number of AES blocks, though each
# file totals one). Every part's header repeats the first part's salt and IV, so a
# later volume cannot be decrypted on its own.
#
# Both methods are kept because they fail differently when the splice is
# wrong: the compressed decoder reads ahead across the boundary and produces
# nothing at all, while the store reader emits the first volume correctly and
# then garbage. One fixture would leave half the failure untested.
rar a -ma5 -ptest -v1k -ep rar5_encrypted_multi.rar "$TMPDIR/large.bin"
echo "  rar5_encrypted_multi.part*.rar"
rar a -ma5 -m0 -ptest -v1k -ep rar5_encrypted_multi_store.rar "$TMPDIR/large.bin"
echo "  rar5_encrypted_multi_store.part*.rar"

# 12. RAR5, archive comment
rar a -ma5 -ep -z"$TMPDIR/comment.txt" rar5_comment.rar "$TMPDIR/hello.txt"
echo "  rar5_comment.rar"

# 13. RAR5, file version
rar a -ma5 -ver -ep rar5_version.rar "$TMPDIR/hello.txt"
# Add it again to create version 2
echo -n "hello rardecode v2" > "$TMPDIR/hello.txt"
rar a -ma5 -ver -ep rar5_version.rar "$TMPDIR/hello.txt"
echo "  rar5_version.rar"

# 14. RAR5, corrupt header (copy valid archive and flip a CRC byte)
cp rar5_store.rar rar5_corrupt_header.rar
# Flip the first byte (part of CRC32) to corrupt it
printf '\xff' | dd of=rar5_corrupt_header.rar bs=1 seek=8 count=1 conv=notrunc 2>/dev/null
echo "  rar5_corrupt_header.rar"

# 15. RAR5, truncated archive
cp rar5_store.rar rar5_truncated.rar
truncate -s 20 rar5_truncated.rar
echo "  rar5_truncated.rar"

# 16. RAR5, empty archive
# Note: RAR 7 erases the archive when deleting the last file.
# An empty archive is just the 8-byte signature + end-of-archive header.
# Skip generation — use a hand-crafted fixture if needed.

# 17. RAR5, locked archive
rar a -ma5 -ep rar5_locked.rar "$TMPDIR/hello.txt"
rar k rar5_locked.rar
echo "  rar5_locked.rar"

# 18. RAR5, recovery record
echo -n "hello rardecode" > "$TMPDIR/hello.txt"
rar a -ma5 -rr -ep rar5_recovery.rar "$TMPDIR/hello.txt"
echo "  rar5_recovery.rar"

# 19. RAR5, x86 branch filter.
#
# The compressor emits its branch filter only when a block's statistics look
# like real machine code — a synthetic byte pattern with dense E8 opcodes does
# not trip the detector, so the payload has to be compiled. exe_filter_src.c
# defines about a thousand small mutually-calling functions, which yields a
# dense field of genuine relative CALL instructions. Built as a bare shared
# object with no libc so the fixture contains only code from this repository.
#
# This is the only fixture that exercises the filter queue at all, and the only
# one big enough that rar adds a quick open service record — which is what
# covers service headers being skipped by Next() rather than surfaced as a file
# named "QO". Do not add -qo- here.
#
# TestExeFixtureReachesFilterPath fails if a regenerated fixture stops queueing
# filters, so a regeneration that silently loses that coverage is caught.
gcc -O0 -fno-inline -shared -nostdlib -fPIC -o "$TMPDIR/own.exe" exe_filter_src.c
# rar a appends to an existing archive, so a re-run would add a second copy.
rm -f rar5_exe_filter.rar
rar a -m5 -ma5 -ep rar5_exe_filter.rar "$TMPDIR/own.exe"
echo "  rar5_exe_filter.rar"

# 20. RAR5, multi-volume with service records in every volume.
#
# Same payload split across 8KB volumes with -rr, so each volume carries a quick
# open and a recovery record after its file block. Covers service records being
# skipped across a split archive, and the filter queue spanning volume
# boundaries. Regenerating must keep producing more than one volume; if the
# payload ever compresses below the volume size the split disappears silently.
rm -f rar5_multi_service.part*.rar
rar a -m5 -ma5 -v8k -rr -ep rar5_multi_service.rar "$TMPDIR/own.exe"
echo "  rar5_multi_service.part*.rar"

# Note: RAR4 archives (-ma4) are not supported by RAR 7.
# If RAR4 test fixtures are needed, use an older version of rar.
#
# 21. RAR5, header-encrypted multi-volume. Every volume repeats its own
# HEAD_CRYPT in plaintext, so a member crossing a boundary is only readable
# if the splice arms header decryption on each new volume, not just the first.
python3 -c "
import random
random.seed(17)
open('$TMPDIR/enchdr.bin','wb').write(bytes(random.getrandbits(8) for _ in range(24000)))
"
rar a -hpsecret -v9k -m0 -ma5 -ep rar5_enchdr_multi.rar "$TMPDIR/enchdr.bin"
echo "  -> rar5_enchdr_multi.part1.rar (+ part2, part3)"

# 22. RAR5, a member too large to decode in one window fill, followed by a
# second member. Abandoning the first mid-block is what leaves the shared
# decoder holding its bit reader; the second member is what that damages.
# The 70 KB of noise ahead of the repeating pattern keeps the expansion
# ratio under the rar-bomb guard, which would otherwise refuse the member
# before it ever decoded.
python3 -c "
import random
random.seed(11)
d = bytes(random.getrandbits(8) for _ in range(70*1024)) + b'ABCDEFGH'*(17*1024*1024//8)
open('$TMPDIR/huge.bin','wb').write(d)
random.seed(5)
w=['w%03d'%i for i in range(200)]
open('$TMPDIR/after.txt','w').write(' '.join(random.choice(w) for _ in range(20000)))
"
rar a -m3 -ma5 -ep rar5_abandon_large.rar "$TMPDIR/huge.bin" "$TMPDIR/after.txt"
echo "  -> rar5_abandon_large.rar"

# 23. RAR3 — NOT generated by this script.
#
# rar 7.x rejects -ma4 outright, so this script cannot produce a RAR3 archive
# at all. rar3_testfile.rar is therefore vendored rather than generated:
#
#   https://github.com/ssokolow/rar-test-files  (build/testfile.rar3.rar)
#
# That repository exists to publish "minimal, legally redistributable" RAR test
# files, generated by its author under a purchased WinRAR license.
#
# It is the only RAR3 archive here that this project did not write itself, and
# so the only check that the RAR3 header parser agrees with a real encoder --
# every other RAR3 test builds its archive in memory and can only confirm our
# writer and reader agree with each other.
#
# It is PPMd-compressed, which this library does not implement, so it cannot be
# read to completion and is excluded from the differential-oracle table. Every
# RAR3 archive in that upstream repository is built from the same small text
# file, which WinRAR compresses with PPMd, so no LZ77 or store-method RAR3
# fixture is available from it. Differential coverage of the RAR3 *decoder*
# therefore remains absent; see TestRAR3_RealArchive_Header for what the
# fixture does cover.

echo ""
echo "=== Done. $(ls -1 *.rar | wc -l) archives generated. ==="
ls -lhS *.rar

