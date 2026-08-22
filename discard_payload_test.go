package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"testing"
)

// Tests for the invariant that no block's declared payload survives into the
// next header read.
//
// The vulnerability these cover (#48) is that a block header may declare
// payload whatever its type -- RAR5 reads DataSize whenever HeaderFlagHasData
// is set, RAR3 whenever longBlock is, and neither consults the block type -- so
// a crafted archive can put a complete, CRC-valid file entry in that region.
// Whatever fails to consume it leaves the next header to be parsed out of
// attacker-chosen bytes, and NextEntry hands back an entry that exists nowhere
// in the archive.
//
// Every test here asserts POSITIONAL recovery: that the entry reached after
// the refusal is the archive's genuine next one. Asserting only that the
// first call errors proves nothing, because it is equally true of the
// vulnerable code -- and asserting only that the payload was "consumed" is
// satisfied by consuming too much, which is what a double-discard does.
//
// Under this rewrite the invariant is enforced in exactly one place --
// volume.next() skips whatever remains of the current block's declared
// payload before it will read the next header, unconditionally and
// regardless of block type -- rather than by a per-case obligation each
// dispatcher had to remember. The fixtures below are unchanged from what they
// were built to attack; only the assertions, which used to check a specific
// switch case's bookkeeping, now check the one property that actually
// matters.

// rar5BlockDeclaring builds a RAR5 block of the given type declaring dataSize
// bytes of payload, with extra appended to the header's own fields.
func rar5BlockDeclaring(blockType uint64, dataSize int, extra []byte, withSig bool) []byte {
	var p bytes.Buffer
	p.Write(EncodeVint(blockType))
	p.Write(EncodeVint(HeaderFlagHasData))
	p.Write(EncodeVint(uint64(dataSize)))
	p.Write(extra)

	var out bytes.Buffer
	if withSig {
		out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	}
	out.Write(rar5Block(p.Bytes()))
	return out.Bytes()
}

// volumesOf returns a closed channel carrying each part as a volume.
func volumesOf(parts ...[]byte) <-chan io.ReadCloser {
	ch := make(chan io.ReadCloser, len(parts))
	for _, p := range parts {
		ch <- &mockReadCloser{bytes.NewReader(p)}
	}
	close(ch)
	return ch
}

// keepReadableVolumes is volumesOf for the terminator tests, named for the
// property they depend on: mockReadCloser's Close does nothing, so its bytes
// stay readable afterwards -- which is what io.NopCloser gives a caller and
// therefore the shape a crafted archive can count on.
//
// The terminator exemption, that undiscarded bytes die with the closed
// volume, is true only because nextVolume drops its reference to it (r.vol is
// set to nil on every failure exit, including a closed channel -- see
// nextVolume in reader.go). Under a ReadCloser that genuinely stopped reads
// these tests would pass against broken code, which is how the exemption came
// to be believed in the first place.
func keepReadableVolumes(parts ...[]byte) <-chan io.ReadCloser {
	return volumesOf(parts...)
}

func fabricatedRAR5() []byte {
	return rar5FileEntry("FABRICATED.txt", 5, crc32.ChecksumIEEE([]byte("owned")), []byte("owned"))
}

// assertReachesRealEntry asserts that the FIRST entry NextEntry returns is
// the archive's genuine next one.
//
// It does not loop. An earlier version called NextEntry in a loop, silently
// closing and skipping any entry whose name did not match before checking
// the next one -- which made it blind to the exact thing these fixtures
// exist to catch: a traversal that hands back a fabricated entry and THEN
// the real one still passed, because the loop skipped the fabricated entry
// without complaint. Asserting only that the first call errors proves
// nothing (equally true of vulnerable code), and asserting only that the
// real entry is eventually reached is satisfied by a traversal that
// fabricates one first -- exactly the bug this helper is supposed to catch.
//
// Every block dispatch() skips silently (a successful archive/service
// header, a crypt header that fails to parse, an exhausted volume) is
// handled INSIDE NextEntry's own loop and never returned to the caller, so
// one call is the right shape here: all four call sites below only ever
// need to skip blocks of that kind before reaching the real entry. A
// fixture that needs the CALLER to walk past a refused, caller-visible
// Entry (one NextEntry hands back terminal, e.g. a rar bomb or
// ErrSolidStreamBroken) does not fit this helper and must not be forced
// into it -- skip_damaged_test.go's tests use Entry.Close() verdicts
// directly for exactly that shape instead.
func assertReachesRealEntry(t *testing.T, r *Reader, wantName string) {
	t.Helper()
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("traversal ended before reaching %q: %v", wantName, err)
	}
	defer func() { _ = e.Close() }()
	if e.Header == nil {
		t.Fatalf("NextEntry returned an entry with no header; want %q", wantName)
	}
	if e.Header.Name != wantName {
		t.Fatalf("NextEntry returned %q, want %q -- an entry other than the "+
			"archive's genuine next one was surfaced, which is the fabrication "+
			"these fixtures exist to detect", e.Header.Name, wantName)
	}
}

// --- Success routes: the block parses, and scanning continues ---------------

func TestArchiveHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	archive.Write(rar5BlockDeclaring(HeaderTypeArchive, len(fabricated), EncodeVint(ArcFlagMultiVol), true))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	assertReachesRealEntry(t, NewReader(volumesOf(archive.Bytes())), "real.txt")
}

// TestServiceHeaderPayloadIsDiscarded_RAR5 covers the default case, which is
// the one that was always correct. It is kept because volume.next() replaced
// three separate per-case discards with one unconditional skip, and this row
// is what proves the ordinary path -- a block dispatch() has no opinion about
// -- is still covered rather than merely assumed.
func TestServiceHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(rar5BlockDeclaring(HeaderTypeService, len(fabricated), nil, false))
	archive.Write(fabricated)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	assertReachesRealEntry(t, NewReader(volumesOf(archive.Bytes())), "real.txt")
}

// --- Error routes: the block is refused, and the payload goes anyway --------

// TestArchiveHeaderParseErrorDiscardsPayload_RAR5 is deleted, not translated.
//
// Its premise was that a failed archive-header parse is a refusal the caller
// may retry past, landing on the real next entry. Dispatch treats an archive
// header parse failure as archive-level fatal instead (reader.go, the
// HeaderTypeArchive case's comment): the archive header defines archive-wide
// semantics, including whether the archive is solid, so a header this library
// cannot parse means proceeding with UNKNOWN archive-wide semantics, not a
// block to discard and scan past. NextEntry therefore returns the parse error
// and nothing further is reachable in that stream -- there is no "resume"
// for this fixture to exercise.
//
// This is not a gap the rewrite left uncovered: it is a deliberate, already
// documented and already tested design decision from the traversal that
// predates this task (see reader.go's HeaderTypeArchive case and
// TestMalformedArchiveHeaderEndsTraversal in reader_test.go, which pins
// exactly this property with its own fixture).
//
// TestCryptHeaderParseErrorDiscardsPayload_RAR5 is deleted, not translated.
//
// Its premise was that a crypt header parse failure is a refusal the caller
// may retry past, landing on the real next entry -- the same "skip rather
// than fatal" treatment ParseFileHeader gets. That premise was wrong: unlike
// a file header, where a bad member is just one entry among many, an
// unparsed HEAD_CRYPT means every header AFTER it in the archive is
// ciphertext this library cannot decrypt. There is no degraded-but-useful
// mode to skip forward into, so dispatch's HeaderTypeEncryption case now
// treats a parse failure as archive-level fatal, exactly like the
// HeaderTypeArchive parse failure covered by
// TestArchiveHeaderParseErrorDiscardsPayload_RAR5's deletion note above and
// pinned by TestMalformedArchiveHeaderEndsTraversal.
//
// The fatal behaviour, including that a real member planted after the
// malformed crypt header is never reached and that the error latches across
// a second NextEntry call, is covered in crypt_header_error_test.go.

// --- Volume-payload routes -------------------------------------------------

// TestVolumeArchiveHeaderPayloadIsDiscarded_RAR5 covers the severe shape. On
// the volume-advance path (nextVolumePayload in splice.go) a header parsed
// out of the undiscarded region would be fed straight into a file already in
// progress as its content, rather than merely surfaced as a spurious entry.
func TestVolumeArchiveHeaderPayloadIsDiscarded_RAR5(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)
	evil := []byte("XXXXXXXXXX")

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotLast,
		uint64(len(whole)), declaredCRC, content1))

	fabricated := rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, evil)

	var vol2 bytes.Buffer
	vol2.Write(rar5BlockDeclaring(HeaderTypeArchive, len(fabricated), EncodeVint(ArcFlagMultiVol), true))
	vol2.Write(fabricated)
	vol2.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, content2))
	vol2.Write(rar5EndHeader())

	r := NewReader(volumesOf(vol1.Bytes(), vol2.Bytes()))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	body, err := io.ReadAll(e)
	if bytes.Contains(body, evil) {
		t.Fatalf("attacker bytes spliced into the file as content: %q (err=%v)", body, err)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q (err=%v)", body, whole, err)
	}
}

// --- The terminator exemption ----------------------------------------------

// TestTerminatorPayloadUnreachableWhenChannelCloses_RAR5 is the regression
// test for the route the terminator exemption missed entirely.
//
// nextVolume closes the current volume, and on a closed channel it must not
// leave r.vol pointing at that volume -- reader.go's nextVolume assigns r.vol
// only on the success path, so a failed advance (including ErrNoNextVolume)
// leaves nothing for a retried NextEntry to read through. Close is no
// defence on its own -- these volumes, like io.NopCloser, keep reading
// afterwards -- so this has to be pinned as a property of the traversal
// rather than assumed from Close's contract.
func TestTerminatorPayloadUnreachableWhenChannelCloses_RAR5(t *testing.T) {
	fabricated := fabricatedRAR5()

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5BlockDeclaring(HeaderTypeEnd, len(fabricated), nil, false))
	vol1.Write(fabricated)

	ch := keepReadableVolumes(vol1.Bytes())

	r := NewReader(ch)
	if _, err := r.NextEntry(); !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("NextEntry: got %v, want ErrNoNextVolume", err)
	}
	if e, err := r.NextEntry(); err == nil {
		t.Fatalf("second NextEntry surfaced %q out of the end header's payload", e.Header.Name)
	}
}

// TestVolumeEndHeaderPayloadDoesNotEatNextVolume_RAR5 covers the other
// direction: over-consuming rather than leaking.
//
// A volume whose only content is an end header claiming a payload it does
// not carry must not have that count applied to the volume opened after it
// -- doing so would eat the real header at the front of the next volume.
// Every other test here has an end header declaring nothing, which makes the
// wrong behaviour a no-op, so this needs its own fixture to make the failure
// mode loud rather than silent.
func TestVolumeEndHeaderPayloadDoesNotEatNextVolume_RAR5(t *testing.T) {
	content1, content2 := []byte("0123456789"), []byte("abcdefghij")
	whole := append(append([]byte{}, content1...), content2...)
	declaredCRC := crc32.ChecksumIEEE(whole)

	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotLast,
		uint64(len(whole)), declaredCRC, content1))

	// A volume holding nothing but an end header that claims a payload. The
	// claim is a lie -- the bytes are not there -- which is the point: the
	// count must never be applied to the volume that opens next.
	var vol2 bytes.Buffer
	vol2.Write(rar5BlockDeclaring(HeaderTypeEnd, 12, nil, true))

	var vol3 bytes.Buffer
	vol3.Write(rar5ArchiveHeader())
	vol3.Write(rar5EntryFlags("split.bin", 0, HeaderFlagHasData|HeaderFlagDataNotFirst,
		uint64(len(whole)), declaredCRC, content2))
	vol3.Write(rar5EndHeader())

	r := NewReader(volumesOf(vol1.Bytes(), vol2.Bytes(), vol3.Bytes()))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	body, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("reading the split file: %v (got %q)", err, body)
	}
	if !bytes.Equal(body, whole) {
		t.Fatalf("content = %q, want %q", body, whole)
	}
}

// --- nextVolume's other invariant-violating exit ---------------------------

// TestBadMagicLeavesNoUsableVolume covers the openVolume failure path.
//
// nextVolume assigns r.vol only once openVolume has succeeded, so a
// bad-magic volume leaves r.vol nil rather than half-opened -- and NextEntry
// treats r.vol == nil as "open the next one", so a caller that retries after
// a bad-magic failure advances cleanly instead of re-reading (or panicking
// on) a volume that never became usable.
func TestBadMagicLeavesNoUsableVolume(t *testing.T) {
	r := NewReader(volumesOf([]byte("not a rar archive at all")))

	if _, err := r.NextEntry(); err == nil {
		t.Fatal("NextEntry: expected a version-detection failure")
	}
	// Must not panic, and must not report success.
	if _, err := r.NextEntry(); err == nil {
		t.Fatal("second NextEntry: expected an error, got success")
	}
}

// --- The sweep: every block type accounts for its declared payload ---------
//
// The per-route tests above prove the routes that were known to be broken.
// The sweep proves the property for the whole type space, including the
// types nobody has thought about, which is the point: this defect has been
// introduced three times by three changes that each handled the cases in
// front of them.
//
// Unlike the old per-case sweep -- which called processHeader directly and
// inspected the engine's internal cursor to prove EACH case in the switch
// discarded correctly -- this one is driven through NextEntry. That is not a
// weakening: it is what the invariant moving into volume.next() means. There
// is no longer a per-case obligation to audit case by case, because
// volume.next() skips a block's declared payload unconditionally, before it
// will read the next header, regardless of what dispatch() did with that
// block. The sweep now proves the invariant holds for the whole type space
// from the one place it is enforced, which is a stronger claim than "each
// case remembered to call the shared helper," not a weaker one.
func TestEveryBlockTypeAccountsForItsPayload_RAR5(t *testing.T) {
	sentinel := rar5FileEntry("SENTINEL.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real"))
	const declared = 9

	// One past HeaderTypeEnd so an unrecognised type is swept too -- that is
	// the case a future block type arrives as.
	for blockType := uint64(HeaderTypeArchive); blockType <= HeaderTypeEnd+1; blockType++ {
		t.Run(hexName(int(blockType)), func(t *testing.T) {
			var stream bytes.Buffer
			stream.Write(rar5ArchiveHeader())
			stream.Write(rar5BlockDeclaring(blockType, declared, nil, false))
			stream.Write(bytes.Repeat([]byte{0xAA}, declared))
			stream.Write(sentinel)

			r := NewReader(volumesOf(stream.Bytes()))

			e, err := r.NextEntry()
			switch blockType {
			case HeaderTypeArchive:
				// Not swept the same way as the rest of the type space: a
				// SECOND archive header mid-stream fails to parse (it carries
				// no archive-flags vint here) and dispatch treats that as
				// archive-level fatal by design -- see
				// TestArchiveHeaderParseErrorDiscardsPayload_RAR5's deletion
				// comment above and TestMalformedArchiveHeaderEndsTraversal
				// in reader_test.go. There is no sentinel to reach.
				if err == nil {
					t.Fatalf("a second, unparsable archive header succeeded, "+
						"returning %q; want the archive-level parse error", e.Header.Name)
				}
				return
			case HeaderTypeEncryption:
				// Also not swept: a crypt header whose payload cannot parse
				// (the stub 0xAA bytes here decode to neither a valid
				// version nor a valid flags vint) is archive-level fatal by
				// design -- see reader.go's HeaderTypeEncryption case and
				// crypt_header_error_test.go. Every header after a real
				// HEAD_CRYPT is ciphertext, so there is no sentinel to
				// reach past an unparsable one.
				if err == nil {
					t.Fatalf("an unparsable crypt header succeeded, "+
						"returning %q; want the archive-level parse error", e.Header.Name)
				}
				return
			case HeaderTypeFile:
				// The stub payload cannot parse as a file header, so this row
				// is refused and swept the same as every other unclaimed
				// type: skipped, and the sentinel is reached next.
			}
			if err != nil {
				t.Fatalf("block type %s: NextEntry did not reach the sentinel: %v", hexName(int(blockType)), err)
			}
			if e.Header.Name != "SENTINEL.txt" {
				t.Fatalf("block type %s: reached %q, want the sentinel -- the "+
					"declared payload was not consumed exactly", hexName(int(blockType)), e.Header.Name)
			}
		})
	}
}

func hexName(v int) string {
	return fmt.Sprintf("type_0x%02x", v)
}

// TestEndHeaderPayloadDoesNotEatNextVolume_RAR5 covers the end-of-volume case
// as reached through the primary dispatch loop (a volume that simply runs
// out), as distinct from the mid-file volume-advance path covered by
// TestVolumeEndHeaderPayloadDoesNotEatNextVolume_RAR5 above. Both need the
// same accounting for the same reason, reached by different code paths, so
// covering one leaves the other free to regress.
func TestEndHeaderPayloadDoesNotEatNextVolume_RAR5(t *testing.T) {
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5BlockDeclaring(HeaderTypeEnd, 40, nil, false))

	var vol2 bytes.Buffer
	vol2.Write(rar5ArchiveHeader())
	vol2.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	vol2.Write(rar5EndHeader())

	assertReachesRealEntry(t, NewReader(volumesOf(vol1.Bytes(), vol2.Bytes())), "real.txt")
}
