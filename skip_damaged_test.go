package rarengine

import (
	"bytes"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// shortEntry declares more content than it carries, so the file ends before
// its declared size with packed bytes still in the stream -- the shape that
// used to cost the caller every file after it.
func shortEntry(name string) []byte {
	return rar5FileEntry(name, 100, 0xdeadbeef, []byte("only ten!!"))
}

func goodEntry(name string, content []byte) []byte {
	return rar5FileEntry(name, uint64(len(content)), crc32.ChecksumIEEE(content), content)
}

// badCRCEntry carries its full declared length but records a checksum the
// content does not match: damage by wrong bytes rather than missing ones.
func badCRCEntry(name string, content []byte) []byte {
	wrong := crc32.ChecksumIEEE(content) ^ 0xffffffff
	return rar5FileEntry(name, uint64(len(content)), wrong, content)
}

// rar5SplitEntry emits a file block marked as continuing into the next volume,
// so reading it drives the multi-volume advance path.
func rar5SplitEntry(name string, unpackedSize uint64, payload []byte) []byte {
	return rar5EntryFlags(name, 0, HeaderFlagHasData|HeaderFlagDataNotLast,
		unpackedSize, 0, payload)
}

// damageFirstEntry runs a Reader up to the point where the leading short file
// has failed and its verdict has been read from Close, and returns the
// Reader positioned to continue.
//
// The three tests below all need that same preamble; sharing it keeps a
// change to how damage is produced or asserted from having to be made three
// times. It asserts rather than assumes each step, so a fixture that stops
// producing a damaged file fails here instead of silently making the
// caller's own assertion vacuous.
func damageFirstEntry(t *testing.T, archive []byte) *Reader {
	t.Helper()

	r := readerFor(archive)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	if e.Header.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; the fixture is not the shape these tests need", e.Header.Name)
	}
	_, _ = io.Copy(io.Discard, e)
	if closeErr := e.Close(); !errors.Is(closeErr, ErrTruncatedFile) {
		t.Fatalf("Close() on the damaged file returned %v; want ErrTruncatedFile", closeErr)
	}
	return r
}

// TestSkipDamagedFile_TraversalContinues is the #30 acceptance test.
//
// A file that ends short leaves packed bytes unread. volume.next() skips
// them unconditionally on the way to the following header, so the stream is
// already at a real block boundary and the files after it are reachable --
// but before this rewrite the caller was handed a bare error indistinguishable
// from "the archive is over", and the only safe reading was to stop. For a
// Usenet download with one damaged segment that meant discarding every
// intact file in the archive.
func TestSkipDamagedFile_TraversalContinues(t *testing.T) {
	good := []byte("second file content, entirely intact")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(goodEntry("good.bin", good))
	archive.Write(rar5EndHeader())

	r := damageFirstEntry(t, archive.Bytes())

	e2, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after a damaged file returned %v; traversal must continue", err)
	}
	if e2.Header.Name != "good.bin" {
		t.Fatalf("continued to %q; want good.bin", e2.Header.Name)
	}
	got, err := io.ReadAll(e2)
	if err != nil {
		t.Fatalf("reading the intact file after a damaged one: %v", err)
	}
	if !bytes.Equal(got, good) {
		t.Errorf("the file after a damaged one decoded to %q; want %q. Skipping "+
			"must not disturb what follows", got, good)
	}
}

// TestSkipDamagedFile_SolidSuccessorRefused pins the case where skipping is
// NOT safe.
//
// Solid files share one LZ77 history. A damaged predecessor never writes the
// bytes its solid successor back-references, so decoding it produces
// plausible-looking output with no marker that it is wrong -- silent
// corruption, which is worse than the lost-files problem skipping solves.
func TestSkipDamagedFile_SolidSuccessorRefused(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	// FileCompSolid: this file's back-references reach into the damaged one.
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	r := damageFirstEntry(t, archive.Bytes())

	e2, err := r.NextEntry()
	if err != nil && !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor NextEntry error = %v, want ErrSolidStreamBroken", err)
	}
	if err == nil {
		if closeErr := e2.Close(); !errors.Is(closeErr, ErrSolidStreamBroken) {
			t.Fatalf("solid successor Close = %v, want ErrSolidStreamBroken", closeErr)
		}
	}
}

// TestSkipDamagedFile_NonSolidSuccessorClearsDamage pins the other half: a
// non-solid file resets the window, so it owes nothing to the damaged file
// and neither does the solid run that starts on top of it. Refusing here
// would make the guard above cost far more than it protects.
func TestSkipDamagedFile_NonSolidSuccessorClearsDamage(t *testing.T) {
	first := []byte("independent file, resets the window")
	second := []byte("solid on top of a clean base!!!")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(goodEntry("independent.bin", first))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(second)),
		crc32.ChecksumIEEE(second), second))
	archive.Write(rar5EndHeader())

	r := damageFirstEntry(t, archive.Bytes())

	e2, err := r.NextEntry()
	if err != nil {
		t.Fatalf("non-solid file after damage returned %v; it resets the "+
			"window and owes the damaged file nothing", err)
	}
	if e2.Header.Name != "independent.bin" {
		t.Fatalf("reached %q; want independent.bin", e2.Header.Name)
	}
	if _, err := io.Copy(io.Discard, e2); err != nil {
		t.Fatalf("reading independent.bin: %v", err)
	}
	if closeErr := e2.Close(); closeErr != nil {
		t.Fatalf("independent.bin Close() = %v, want nil", closeErr)
	}

	e3, err := r.NextEntry()
	if err != nil {
		t.Fatalf("solid file built on a clean base returned %v; the damage was "+
			"cleared by the non-solid file before it", err)
	}
	if e3.Header.Name != "solid.bin" {
		t.Fatalf("reached %q; want solid.bin", e3.Header.Name)
	}
	if closeErr := e3.Close(); closeErr != nil {
		t.Fatalf("solid.bin built on a clean base Close() = %v, want nil", closeErr)
	}
}

// TestSkipDamagedFile_ResetClearsDamage pins that damage belongs to the
// stream that caused it. A reused Reader refusing the next archive's solid
// files over an unrelated failure would be a leak of exactly the kind Reset
// exists to prevent.
func TestSkipDamagedFile_ResetClearsDamage(t *testing.T) {
	var damagedArchive bytes.Buffer
	damagedArchive.Write(rar5ArchiveHeader())
	damagedArchive.Write(shortEntry("truncated.bin"))
	damagedArchive.Write(rar5EndHeader())

	r := damageFirstEntry(t, damagedArchive.Bytes())

	content := []byte("a fresh archive, solid from the start")
	var fresh bytes.Buffer
	fresh.Write(rar5ArchiveHeader())
	fresh.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(content)),
		crc32.ChecksumIEEE(content), content))
	fresh.Write(rar5EndHeader())

	r.Reset(volumesOf(fresh.Bytes()))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("a solid file in a fresh archive returned %v; the previous "+
			"stream's damage must not reach it", err)
	}
	if e.Header.Name != "solid.bin" {
		t.Fatalf("reached %q; want solid.bin", e.Header.Name)
	}
	if closeErr := e.Close(); closeErr != nil {
		t.Fatalf("solid.bin after Reset Close() = %v, want nil", closeErr)
	}
}

// alwaysFailsAfter serves data and then fails with the same non-EOF error on
// every subsequent call.
type alwaysFailsAfter struct {
	data   []byte
	off    int
	failAt int
	err    error
}

func (a *alwaysFailsAfter) Read(p []byte) (int, error) {
	if a.off >= a.failAt {
		return 0, a.err
	}
	n := min(len(p), a.failAt-a.off)
	copy(p, a.data[a.off:a.off+n])
	a.off += n
	return n, nil
}

// TestSkipDamagedFile_ShortDrainNeverFabricates covers a truncated volume:
// the promised bytes are simply not on the media, so volume.next()'s skip
// stops early and the following header read fails too.
//
// Structurally, NextEntry can never return both an error and an entry --
// so a non-nil error here is already proof that nothing was fabricated out
// of whatever bytes happened to sit where the header read gave up.
func TestSkipDamagedFile_ShortDrainNeverFabricates(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	full := archive.Bytes()

	r := readerFor(full[:len(full)-4])
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	_, _ = io.Copy(io.Discard, e)
	_ = e.Close()

	if _, err := r.NextEntry(); err == nil {
		t.Fatal("NextEntry succeeded after a short drain; the stream is " +
			"wherever the media ran out, so there is nothing safe to return")
	}
}

// TestSkipDamagedFile_FailedDrainSurfacesTheRealError covers the other
// unsettled case: the drain itself hard-errors, so the offset is unknown
// rather than merely past the end of the media. The failure must reach the
// caller as itself, not be silently converted into a clean end of archive.
func TestSkipDamagedFile_FailedDrainSurfacesTheRealError(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	full := archive.Bytes()

	readErr := errors.New("media failed mid-payload")
	src := &alwaysFailsAfter{data: full, failAt: len(full) - 4, err: readErr}

	r := NewReader(volumesOf2(src))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	_, _ = io.Copy(io.Discard, e)
	_ = e.Close()

	if _, err := r.NextEntry(); !errors.Is(err, readErr) {
		t.Fatalf("got %v; want the underlying media error surfaced, not "+
			"silently converted to a clean end of archive", err)
	}
}

// volumesOf2 wraps a single already-built io.Reader as one volume, for
// fixtures whose reader needs its own failure behaviour rather than being
// built from a plain byte slice.
func volumesOf2(r io.Reader) <-chan io.ReadCloser {
	ch := make(chan io.ReadCloser, 1)
	ch <- &mockReadCloser{r}
	close(ch)
	return ch
}

// TestSkipDamagedFile_SolidRefusedAcrossVolumeAfterTruncation is the
// regression test for the case damage tracking originally missed.
//
// A truncated volume takes the short-drain path. While damage was recorded
// from the caller-visible error rather than from what happened to the file,
// this left the window looking intact -- and a solid file opening the NEXT
// volume was admitted, decoding against a window its predecessor never
// finished writing. That is the ordinary Usenet shape: one segment lost, the
// remaining volumes intact.
func TestSkipDamagedFile_SolidRefusedAcrossVolumeAfterTruncation(t *testing.T) {
	// Volume 1: a file declaring far more payload than the media carries.
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5FileEntry("truncated.bin", 1000, 0xdeadbeef, make([]byte, 1000)))
	truncated := vol1.Bytes()[:vol1.Len()-990]

	// Volume 2: intact, opening with a solid entry that back-references the
	// history volume 1 failed to write.
	content := []byte("solid content depending on history")
	var vol2 bytes.Buffer
	vol2.Write(rar5ArchiveHeader())
	vol2.Write(rar5EntryComp("solid.bin", FileCompSolid, uint64(len(content)),
		crc32.ChecksumIEEE(content), content))
	vol2.Write(rar5EndHeader())

	r := NewReader(volumesOf(truncated, vol2.Bytes()))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	if e.Header.Name != "truncated.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", e.Header.Name)
	}
	n, err := io.Copy(io.Discard, e)
	if err == nil {
		t.Fatal("reading the truncated file reported success")
	}
	// Guards the fixture: if the file somehow delivered everything it
	// declared, there is no damage and the assertion below proves nothing.
	if n >= 1000 {
		t.Fatalf("the file delivered %d of 1000 bytes, so it is not truncated", n)
	}
	if closeErr := e.Close(); closeErr == nil {
		t.Fatal("the truncation was not reported by Close")
	}

	// The next call advances to volume 2. That is the call the damage state
	// has to survive to.
	e2, err := r.NextEntry()
	if err != nil && !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid file opening the next volume after a truncated one "+
			"returned %v; want ErrSolidStreamBroken. Its back-references reach "+
			"into %d bytes that were never written", err, 1000-n)
	}
	if err == nil {
		if closeErr := e2.Close(); !errors.Is(closeErr, ErrSolidStreamBroken) {
			t.Fatalf("solid file opening the next volume after a truncated one "+
				"Close() = %v; want ErrSolidStreamBroken", closeErr)
		}
	}
}

// TestSkipDamagedFile_AbandonedAdvanceNeverFabricates is the regression test
// for the fabrication a failed volume advance nearly enabled.
//
// A header that fails its CRC after consuming some bytes leaves the volume
// poisoned at whatever offset it gave up at -- an offset the archive itself
// chose, since the bytes that fail the CRC also decide how far the reader
// got before giving up. CLAUDE.md names parsing a header out of that offset
// as the class this library must never allow.
//
// Structurally, NextEntry cannot return both a name and an error, so proving
// no fabrication reduces to: this returns an error.
func TestSkipDamagedFile_AbandonedAdvanceNeverFabricates(t *testing.T) {
	// Volume 1: a file whose payload continues into the next volume.
	var vol1 bytes.Buffer
	vol1.Write(rar5ArchiveHeader())
	vol1.Write(rar5SplitEntry("a.bin", 500, []byte("ten bytes!")))

	// Volume 2: a header that parses far enough to consume bytes and then
	// fails its CRC, followed by an entry the archive would like surfaced.
	pwned := []byte("ATTACKER CONTROLLED BYTES")
	var vol2 bytes.Buffer
	vol2.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	// Sized so the parser consumes exactly these 8 bytes and stops ON the
	// planted entry: ReadBlockHeader reads 7, decodes a 1-byte size vint of 3,
	// then reads bufSize-3 = 1 more. The CRC then fails. An oversized vint
	// here would make it swallow the rest of the volume instead, and the
	// planted entry would be unreachable.
	vol2.Write([]byte{0xff, 0xff, 0xff, 0xff, 0x03, 0xaa, 0xbb, 0xcc})
	vol2.Write(goodEntry("PWNED.bin", pwned))
	vol2.Write(rar5EndHeader())

	r := NewReader(volumesOf(vol1.Bytes(), vol2.Bytes()))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	if e.Header.Name != "a.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", e.Header.Name)
	}
	_, _ = io.Copy(io.Discard, e)
	_ = e.Close()

	if _, err := r.NextEntry(); err == nil {
		t.Fatal("NextEntry reported success after a failed volume advance; " +
			"the offset it would have parsed from was chosen by the archive")
	}
}

// TestSkipDamagedFile_SolidRefusalDropsPayload pins that ErrSolidStreamBroken
// obeys the rule every other refusal in this package obeys.
//
// CLAUDE.md: "Refusing a file means dropping its payload, whatever the reason
// for the refusal ... Do not narrow it to particular errors." A refused
// block that keeps its payload supplies the next entry, because traversal
// continues afterwards. This refusal is checked the same way as every other:
// what the caller reaches next must be the archive's real next entry, not
// whatever the refused block's own smuggled payload contains.
func TestSkipDamagedFile_SolidRefusalDropsPayload(t *testing.T) {
	// The solid file's payload is itself a well-formed entry. If the refusal
	// leaves those bytes in the stream, the next header is parsed out of them.
	pwned := []byte("ATTACKER CONTROLLED BYTES")
	smuggled := goodEntry("PWNED.bin", pwned)

	tail := []byte("the real next file")
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(shortEntry("truncated.bin"))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid,
		uint64(len(smuggled)), 0x1234, smuggled))
	archive.Write(goodEntry("legit.bin", tail))
	archive.Write(rar5EndHeader())

	r := damageFirstEntry(t, archive.Bytes())

	e2, err := r.NextEntry()
	if err != nil && !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("the solid file was not refused (%v); this test cannot check "+
			"what a refusal drops if nothing was refused", err)
	}
	if err == nil {
		if closeErr := e2.Close(); !errors.Is(closeErr, ErrSolidStreamBroken) {
			t.Fatalf("solid file Close() = %v; want ErrSolidStreamBroken", closeErr)
		}
	}

	// Traversal continues, so whatever the refusal left behind is what gets
	// parsed next.
	e3, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after a refusal returned %v; the refused payload "+
			"should have been dropped, leaving the stream on the next real "+
			"header", err)
	}
	if e3.Header.Name == "PWNED.bin" {
		t.Fatalf("the refused file's payload supplied the next entry: got %q. "+
			"ErrSolidStreamBroken must drop the payload like every other "+
			"refusal, or it becomes a header-fabrication route", e3.Header.Name)
	}
	if e3.Header.Name != "legit.bin" {
		t.Fatalf("reached %q; want legit.bin", e3.Header.Name)
	}
	got, err := io.ReadAll(e3)
	if err != nil {
		t.Fatalf("reading the file after a refusal: %v", err)
	}
	if !bytes.Equal(got, tail) {
		t.Errorf("the file after a refusal decoded to %q; want %q", got, tail)
	}
}

// TestSkipDamagedFile_ChecksumFailureIsContinuable covers the commonest
// damage signal in the workload this feature targets.
//
// A file that reached its declared size and then failed its CRC32 is just as
// skippable as a truncated one: the packed bytes are drained by volume.next()
// on the way to the next header regardless of how the file ended.
func TestSkipDamagedFile_ChecksumFailureIsContinuable(t *testing.T) {
	tail := []byte("an entirely intact second file")

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(badCRCEntry("bad.bin", []byte("content whose CRC will not match")))
	archive.Write(goodEntry("good.bin", tail))
	archive.Write(rar5EndHeader())

	r := readerFor(archive.Bytes())
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	if e.Header.Name != "bad.bin" {
		t.Fatalf("first entry is %q; fixture is not the shape this tests", e.Header.Name)
	}
	_, _ = io.Copy(io.Discard, e)
	if closeErr := e.Close(); !errors.Is(closeErr, ErrCRCMismatch) {
		t.Fatalf("Close() on the mismatched file returned %v; want ErrCRCMismatch", closeErr)
	}

	e2, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after the CRC mismatch returned %v; traversal "+
			"could continue", err)
	}
	if e2.Header.Name != "good.bin" {
		t.Fatalf("continued to %q; want good.bin", e2.Header.Name)
	}
}

// TestSkipDamagedFile_ChecksumFailureDamagesWindow pins the other half. A
// file whose CRC32 did not match wrote the WRONG bytes into the shared
// history, so a solid successor decodes against content the archive never
// assumed -- silently, since nothing in the format marks it.
func TestSkipDamagedFile_ChecksumFailureDamagesWindow(t *testing.T) {
	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(badCRCEntry("bad.bin", []byte("content whose CRC will not match")))
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	r := readerFor(archive.Bytes())
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	_, _ = io.Copy(io.Discard, e)
	if closeErr := e.Close(); !errors.Is(closeErr, ErrCRCMismatch) {
		t.Fatalf("Close() on bad.bin returned %v; want ErrCRCMismatch, or this "+
			"test is not exercising a checksum failure", closeErr)
	}

	e2, err := r.NextEntry()
	if err != nil && !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a solid file after a CRC-mismatched one returned %v; want "+
			"ErrSolidStreamBroken. Its back-references reach into bytes known "+
			"to be wrong", err)
	}
	if err == nil {
		if closeErr := e2.Close(); !errors.Is(closeErr, ErrSolidStreamBroken) {
			t.Fatalf("solid file after a CRC-mismatched one Close() = %v; want "+
				"ErrSolidStreamBroken", closeErr)
		}
	}
}

// TestSkipDamagedFile_RefusedFileDamagesWindow covers a file that never
// decoded at all.
//
// A refusal drops the payload and never begins the entry, so it never writes
// anything to the shared window. That is nonetheless absent history a solid
// successor's back-references assume is there. Window.CopyBytes bounds
// distances by the history actually written, but the shortfall here sits
// INSIDE that bound -- the successor would read an earlier file's bytes
// rather than reading past the end -- so nothing else catches it.
func TestSkipDamagedFile_RefusedFileDamagesWindow(t *testing.T) {
	// A rar bomb: declared unpacked size far exceeds both 1 MiB and 1000x the
	// packed size, so dispatch refuses it before any decoding.
	bomb := rar5FileEntry("bomb.bin", 2*1024*1024, 0x1234, []byte("ten bytes!"))

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(bomb)
	archive.Write(rar5EntryComp("solid.bin", FileCompSolid, 20, 0x1234,
		[]byte("twenty bytes exactly")))
	archive.Write(rar5EndHeader())

	r := readerFor(archive.Bytes())

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry #1: %v", err)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrRarBombDetected) {
		t.Fatalf("Close() on the bomb entry returned %v; want ErrRarBombDetected, "+
			"or this test is not exercising a refusal", closeErr)
	}

	e2, err := r.NextEntry()
	if err != nil && !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("a solid file after a refused one returned %v; want "+
			"ErrSolidStreamBroken. The refused file contributed nothing to "+
			"the window it back-references", err)
	}
	if err == nil {
		if closeErr := e2.Close(); !errors.Is(closeErr, ErrSolidStreamBroken) {
			t.Fatalf("solid file after a refused one Close() = %v; want "+
				"ErrSolidStreamBroken", closeErr)
		}
	}
}

// errWithFinalBytes delivers its data and reports err alongside the last of
// it, the shape a decoder takes when it fails on a file's final block: the
// byte budget is satisfied, and the bytes are still suspect.
type errWithFinalBytes struct {
	data []byte
	off  int
	err  error
}

func (e *errWithFinalBytes) Read(p []byte) (int, error) {
	if e.off >= len(e.data) {
		return 0, e.err
	}
	n := copy(p, e.data[e.off:])
	e.off += n
	if e.off >= len(e.data) {
		return n, e.err
	}
	return n, nil
}

// TestFinishActive_DamageOnNonCleanOutcome covers a file that met its
// declared size and still failed.
//
// A decoder that errors on the final block -- an invalid Huffman code, a
// corrupt bitstream, bad AES padding -- returns the last bytes together with
// the error, so remaining reaches zero and Read takes finish(err) without
// ever running verifyChecksum. The file is neither short nor CRC-mismatched,
// but the bytes it put in the window are whatever the decoder produced
// before it gave up, and a solid successor back-references them.
//
// ErrChecksumUnsupported is deliberately NOT damage: that file decoded
// normally and the library simply cannot check its digest. Treating every
// non-nil outcome as damage would refuse the solid successors of every
// encrypted file recording a MAC, which decode correctly.
//
// This drives Reader.finishActive directly, as the old per-site test drove
// fileReader.endFile directly: the decision is a three-way classification
// with no natural home in a round-tripped archive (a decode error exactly at
// the final byte is not reproducible through a legitimate fixture in any
// reasonable way), so it is pinned as a unit, observing its effect the same
// way production code does -- through Window.BeginFile.
func TestFinishActive_DamageOnNonCleanOutcome(t *testing.T) {
	content := []byte("bytes the decoder produced before it gave up")

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"decode error on the final block", errors.New("invalid huffman code"), true},
		{"unverifiable digest", ErrChecksumUnsupported, false},
		{"clean completion", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReader(nil)
			// LastBlock is what a parsed single-block header carries, and
			// saying so matters: the zero value is false, which claims the
			// member continues into another part -- and a member that
			// reaches its declared size while that claim stands is refused
			// as malformed, which would make every case here damage.
			fh := &FileHeader{
				Name: "x.bin", UnpackedSize: int64(len(content)), LastBlock: true,
			}
			e := newEntry(fh, &errWithFinalBytes{data: content, err: tc.err})
			r.entry = e

			_, _ = io.Copy(io.Discard, e)
			if e.remaining != 0 {
				t.Fatalf("remaining = %d; this case must reach the byte budget, "+
					"or it is testing the short path instead", e.remaining)
			}

			r.finishActive()

			// Observe the effect the same way a solid member's admission does:
			// BeginFile(true) refuses iff the window was left incomplete.
			gotDamaged := errors.Is(r.win.BeginFile(true), ErrSolidStreamBroken)
			if gotDamaged != tc.want {
				t.Errorf("damaged = %v, want %v for outcome %v", gotDamaged, tc.want, tc.err)
			}
		})
	}
}
