#!/bin/bash
# generate.sh — Regenerates all RAR test fixtures from scratch.
#
# Requirements: rar (v5+), ln -s
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

# Note: RAR4 archives (-ma4) are not supported by RAR 7.
# If RAR4 test fixtures are needed, use an older version of rar.

echo ""
echo "=== Done. $(ls -1 *.rar | wc -l) archives generated. ==="
ls -lhS *.rar

