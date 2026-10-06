#!/bin/bash
# generate.sh — Regenerates all RAR test fixtures from scratch.
#
# Requirements: rar (v5+), ln -s, python3, gcc (for the x86 filter fixture),
# go and objcopy from binutils (for the sweep fixture, section 26)
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

# 5b. RAR5, BLAKE2sp hash AND file encryption (password: "test").
# Sets UseMac over a BLAKE2sp digest with no CRC32 field present, which is the
# combination that proved uncheckableDigest was naming a field the header does
# not carry. See TestUncheckableDigestNamesWhatTheHeaderActuallyRecords.
rar a -ma5 -htb -p'test' -ep rar5_blake2_encrypted.rar "$TMPDIR/hello.txt"
echo "  rar5_blake2_encrypted.rar"

# 5c. RAR7 format, and the RAR5 archive one step below the boundary.
#
# RAR 7.0 is not selected by a switch -- there is no -ma7. It is selected by
# needing a dictionary larger than RAR5 can express. RAR5 records the
# dictionary as a 4-bit exponent (128KB << n), so n=15 is 4 GB and that is the
# ceiling; asking for more raises the file header's unpack-version field to 1
# and puts the excess in bits above 14. Measured, so the boundary is not
# folklore:
#
#   -md4g -> VERSION=0 dictbits=15 extra=0x00   <- rar5_dict4g.rar
#   -md5g -> VERSION=1 dictbits=15 extra=0x10   <- rar7_unpack_version.rar
#
# The content is piped through stdin (-si) rather than given as a file, and
# that is load-bearing: when rar knows the input size it shrinks the dictionary
# to fit, so `rar a -md5g small.txt` writes a 128 KB dictionary and VERSION=0.
# Reading from a pipe it cannot know the size, so it keeps what -md asked for.
# This is what makes a genuine RAR7 archive 106 bytes instead of 5 GB.
#
# Both signatures are byte-identical to every other RAR5 archive here -- that
# is the whole point of the pair. Nothing outside a file header separates the
# formats, which is why the version field has to be checked.
#
# Note unrar will not EXTRACT rar7_unpack_version.rar without -md5g: it
# declines to allocate a dictionary that large by default. It lists it fine,
# and rarengine refuses it on the version before any window work, so neither
# needs the switch.
printf 'hello rardecode' | rar a -si"hello.txt" -md5g -m1 -inul rar7_unpack_version.rar
echo "  rar7_unpack_version.rar"
printf 'hello rardecode' | rar a -si"hello.txt" -md4g -m1 -inul rar5_dict4g.rar
echo "  rar5_dict4g.rar"

# 5c'. The declared dictionary size at several exponents, for
# TestFileHeaderDictSizeAgainstRealArchives. Same -si trick as above, for the
# same reason: with a known input size rar shrinks the dictionary to fit and
# every row would read 128 KB.
for md in 128k 1m 32m 64m 1g; do
    printf 'hello rardecode' | rar a -si"hello.txt" -md$md -m1 -inul "rar5_dict_$md.rar"
    echo "  rar5_dict_$md.rar"
done

# 5d. RAR5, MIXED encryption: one unencrypted member, then an encrypted one.
# Two separate `rar a` invocations -- a single one applies one policy to every
# file. unrar lists the second with a leading '*'. This is the archive that
# showed VerifyPassword must not answer from the first member alone.
printf 'plain content' > "$TMPDIR/plain.txt"
printf 'secret content' > "$TMPDIR/secret.txt"
rar a -ep -inul rar5_mixed_encryption.rar "$TMPDIR/plain.txt"
rar a -ep -p'test' -inul rar5_mixed_encryption.rar "$TMPDIR/secret.txt"
echo "  rar5_mixed_encryption.rar"

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

# 23. RAR5, BLAKE2sp (-htb) members large enough to mean something.
#
# rar5_blake2.rar above is 15 bytes: less than one BLAKE2s block, so it never
# reaches a second lane. These cross every lane many times over and hit a
# partial final block.
#
# 23a. Single volume, compressed, 1,200,037 bytes (over 1 MiB, not a multiple
# of 64). The content is a 3000-byte noise block repeated, which keeps the
# archive a few KB while the expansion ratio (~400) stays under the rar-bomb
# guard that refuses 1000x on members over 1 MB.
#
# 23b. Multi-volume, stored. 23c. Multi-volume, compressed. Measured with rar
# 7.12 on archives of 3 to 6 volumes in both methods: under -htb EVERY part
# records a BLAKE2 digest and NONE records a CRC32 (under -htc it is the
# reverse). On a non-final part that digest covers the part's PACKED bytes
# ("Pack-BLAKE2" in `unrar lt`); only the final part's is the whole-file hash.
# That is what lets the first header decide whether to hash at all, and
# TestBlake2spMultiVolumeFirstHeaderDecides pins it against these fixtures.
#
# Keep the volume sizes small enough to produce at least three parts.
python3 - "$TMPDIR" <<'PY'
import random, sys
d = sys.argv[1]
random.seed(78)
blk = bytes(random.getrandbits(8) for _ in range(3000))
open(d + '/b2_large.bin', 'wb').write((blk * 401)[:1200037])
random.seed(79)
open(d + '/b2_store.bin', 'wb').write(bytes(random.getrandbits(8) for _ in range(6001)))
random.seed(80)
w = [''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(3, 9))) for _ in range(900)]
open(d + '/b2_comp.bin', 'w').write(' '.join(random.choice(w) for _ in range(3500)))
PY
rm -f rar5_blake2_large.rar rar5_blake2_store_multi.part*.rar rar5_blake2_comp_multi.part*.rar
rar a -m3 -ma5 -htb -ep -inul rar5_blake2_large.rar "$TMPDIR/b2_large.bin"
echo "  rar5_blake2_large.rar"
rar a -m0 -ma5 -htb -v2k -ep -inul rar5_blake2_store_multi.rar "$TMPDIR/b2_store.bin"
echo "  rar5_blake2_store_multi.part*.rar"
rar a -m3 -ma5 -htb -v3k -ep -inul rar5_blake2_comp_multi.rar "$TMPDIR/b2_comp.bin"
echo "  rar5_blake2_comp_multi.part*.rar"

# 24. RAR5 link members: a symlink, a hard link, a link in the MIDDLE of a solid
# archive, and a hard link whose target is over 1 MiB.
#
# A link is a file header carrying a redirection extra record (type 5) and no
# payload: Packed size is 0 and the CRC32 field is present but zero. The
# declared size is NOT a content size -- for a symlink it is the length of the
# target string, for a hard link it is the size of the file it points at.
#
# Everything runs inside $LINKDIR with -ep so the member names (and the link
# targets, which rar records as given) are bare file names.
LINKDIR="$TMPDIR/links"
mkdir -p "$LINKDIR"
OUTDIR="$(pwd)"
rm -f rar5_link_symlink.rar rar5_link_hard.rar rar5_link_solid.rar rar5_link_hard_large.rar
(
  cd "$LINKDIR"
  printf 'real text' > real.txt
  ln -s real.txt link.txt
  printf 'orig content' > orig.txt
  ln orig.txt hard.txt
  rar a -ol -ma5 -m0 -ep -inul "$OUTDIR/rar5_link_symlink.rar" real.txt link.txt
  rar a -oh -ma5 -m0 -ep -inul "$OUTDIR/rar5_link_hard.rar" orig.txt hard.txt

  # Solid, with the link in the middle. -ds stops rar sorting its input, so the
  # link really is the second of three members -- without it rar stores links
  # last and nothing follows one, which proves nothing about the window. The
  # third member is short enough that rar encodes it almost entirely as a
  # back-reference into the first, so it only decodes if the link left the
  # window history alone.
  printf 'AAAA first member text, compressible compressible compressible' > a.txt
  printf 'BBBB third member text, compressible compressible compressible a.txt' > c.txt
  ln -s a.txt mid.lnk
  rar a -s -ds -ol -ma5 -m3 -ep -inul "$OUTDIR/rar5_link_solid.rar" a.txt mid.lnk c.txt

  # A hard link declaring 1100000 bytes -- over the 1 MiB rar-bomb threshold --
  # with a packed size of zero. The target is added so rar records the link,
  # then deleted so the fixture stays under 100 bytes; the link member's header
  # is unaffected.
  head -c 1100000 /dev/zero > z.bin
  ln z.bin zhard.bin
  rar a -oh -ma5 -m5 -ep -inul "$OUTDIR/rar5_link_hard_large.rar" z.bin zhard.bin
  rar d -inul "$OUTDIR/rar5_link_hard_large.rar" z.bin
)
echo "  rar5_link_{symlink,hard,solid,hard_large}.rar"

# 25. RAR5, bomb-ratio boundary: 64 MiB of zeros (ratio between 1000:1 and 65536:1)
#
# This archive tests the bomb-guard boundary. 64 MiB of zeros compresses to 2,779 bytes
# with -m3 (method 3), giving a ratio of ~24,150:1. This ratio the old 1000:1 guard
# refused and the new 65536:1 guard admits. The archive decodes and verifies without
# ErrRarBombDetected.
dd if=/dev/zero of="$TMPDIR/zeros_64m.bin" bs=1M count=64 2>/dev/null
rar a -m3 -ma5 -ep rar5_zeros_bomb_ratio.rar "$TMPDIR/zeros_64m.bin"
echo "  rar5_zeros_bomb_ratio.rar"

# 26. RAR5, small multi-block solid archive for the damaged-input sweep.
#
# Three members in this order (-ds keeps it; rar would otherwise sort the .jpg
# last): about 860 KB of this package's own Go source (6 blocks, each carrying
# new tables), 4096 random bytes stored via -msjpg, and 200000 bytes of an
# x86-64 Go binary's .text (rar emits an E8 filter for it). Only code from this
# repository's toolchain goes in. The text changes as the package does, so a
# regeneration is a different archive; TestSweepFixtureShape pins the shape,
# and testdata/decode_golden.tsv must be regenerated with it.
mkdir -p "$TMPDIR/sweepmain"
cat > "$TMPDIR/sweepmain/main.go" <<'GO'
package main

import (
	"fmt"
	"net/http"
)

func main() { fmt.Println(http.StatusText(200)) }
GO
printf 'module sweepx\ngo 1.22\n' > "$TMPDIR/sweepmain/go.mod"
(cd "$TMPDIR/sweepmain" && go build -o ../sweepx .)
objcopy -O binary --only-section=.text "$TMPDIR/sweepx" "$TMPDIR/sweep_text.bin"
cat ../*.go > "$TMPDIR/a_text.txt"
head -c 4096 /dev/urandom > "$TMPDIR/b_stored.jpg"
tail -c +400001 "$TMPDIR/sweep_text.bin" | head -c 200000 > "$TMPDIR/c_code.exe"
rm -f rar5_sweep.rar
rar a -ma5 -ep -s -ds -m3 -md32m -msjpg rar5_sweep.rar \
    "$TMPDIR/a_text.txt" "$TMPDIR/b_stored.jpg" "$TMPDIR/c_code.exe"
echo "  rar5_sweep.rar"

echo ""
echo "=== Done. $(ls -1 *.rar | wc -l) archives generated. ==="
ls -lhS *.rar

