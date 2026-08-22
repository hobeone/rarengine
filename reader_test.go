package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type mockReadCloser struct {
	io.Reader
}

func (m *mockReadCloser) Close() error { return nil }

// fixtureBytes loads an on-disk archive. These are unrar-produced, so a
// truncation test against them exercises real header layouts rather than the
// hand-built ones the in-memory builders produce.
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

// multiVolumeChan feeds the ten rar5_multi parts in order. trimFirst, when
// non-negative, cuts that many bytes off the end of part01 so the file's
// payload runs short there and the reader has to advance mid-file.
func multiVolumeChan(t *testing.T, trimFirst int) <-chan io.ReadCloser {
	t.Helper()

	names := make([]string, 0, 10)
	for i := 1; i <= 9; i++ {
		names = append(names, fmt.Sprintf("rar5_multi.part0%d.rar", i))
	}
	names = append(names, "rar5_multi.part10.rar")

	volumes := make(chan io.ReadCloser, len(names))
	for i, name := range names {
		b := fixtureBytes(t, name)
		if i == 0 && trimFirst >= 0 {
			if trimFirst >= len(b) {
				t.Fatalf("trim %d exceeds part01 length %d", trimFirst, len(b))
			}
			b = b[:len(b)-trimFirst]
		}
		volumes <- &mockReadCloser{bytes.NewReader(b)}
	}
	close(volumes)
	return volumes
}

// readerFor builds a Reader over a single in-memory volume.
func readerFor(data []byte) *Reader {
	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(data)}
	close(volumes)
	return NewReader(volumes)
}

// The whole point of the rewrite, asserted end to end: a fabricated file entry
// planted in an unclaimed block's payload must never be returned as a member.
func TestNextEntrySkipsFabricatedHeaderInPayload(t *testing.T) {
	planted := fabricatedRAR5()
	// extra carries the archive header's own body (its flags vint) so
	// ParseArchiveHeader succeeds and the block is legitimately skipped --
	// this test is about payload discarding, not archive-header parsing,
	// which is pinned separately by TestMalformedArchiveHeaderEndsTraversal.
	archive := rar5BlockDeclaring(HeaderTypeArchive, len(planted), EncodeVint(0), true)
	stream := append(append([]byte{}, archive...), planted...)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err == nil {
		t.Fatalf("NextEntry returned member %q, which exists nowhere in the "+
			"archive -- it was parsed out of the archive header's payload",
			e.Header.Name)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNoNextVolume) {
		t.Fatalf("NextEntry error = %v, want io.EOF or ErrNoNextVolume", err)
	}
}

// A rar bomb is refused as a terminal Entry, not as an error from NextEntry.
func TestRarBombIsRefusedAsTerminalEntry(t *testing.T) {
	r := NewReader(volumesOf(rarBombArchive(t)))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if err := e.Close(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("Close = %v, want ErrRarBombDetected", err)
	}
}

// A member whose file header does not parse is skipped, and the archive stays
// readable past it. Under the old design this ended the traversal, because
// nothing could say where the stream was.
func TestUnparsableFileHeaderDoesNotEndTraversal(t *testing.T) {
	stream := archiveWithBadFileHeaderThen(t, "good.bin", "payload")

	r := NewReader(volumesOf(stream))
	for {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("traversal ended before reaching the good member: %v", err)
		}
		if e.Header != nil && e.Header.Name == "good.bin" {
			_ = e.Close()
			return
		}
		_ = e.Close()
	}
}

// A solid member following a damaged one is refused rather than decoded
// against history its predecessor never wrote.
func TestSolidMemberAfterDamageIsRefused(t *testing.T) {
	r := NewReader(volumesOf(truncatedThenSolidArchive(t)))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("first member verdict = %v, want ErrTruncatedFile", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if err := second.Close(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}

// A refused member (a rar bomb) whose block declares more payload than is
// actually present in the volume must never let the planted, CRC-valid block
// sitting immediately after the truncated payload surface as a member.
//
// This replaces coverage deleted earlier in the plan: the deleted test
// asserted that a refusal whose payload drop came up SHORT must not promise
// the traversal can continue. Here the shortfall comes from a block that lies
// about how much payload follows it, rather than from a truncated volume
// mid-skip -- both are the same hazard (a header parsed out of unclaimed
// payload), reached by different means.
func TestRefusedMemberWithTruncatedPayloadDoesNotFabricateNextEntry(t *testing.T) {
	planted := fabricatedRAR5()

	// The block carries NO real content: the planted block sits at byte zero
	// of what the header calls "payload". If next() ever failed to perform
	// the skip, a header read from that position would land exactly on the
	// planted block's CRC-valid file header. The declared packed size is the
	// planted block's length plus a margin, so the declared-vs-actual
	// mismatch is what makes this a truncated payload: skipping the declared
	// amount runs the volume dry before any header could be read from it.
	declaredPacked := int64(len(planted) + 1000)

	bomb := rar5Member(t, memberSpec{
		name:       "bomb.bin",
		content:    "",
		unpackedSz: 2 << 30, // 2 GiB declared, so the bomb guard fires
		packedSz:   declaredPacked,
	})
	archive := rar5Archive(t, false, bomb)
	stream := append(append([]byte{}, archive...), planted...)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrRarBombDetected) {
		t.Fatalf("first member verdict = %v, want ErrRarBombDetected", err)
	}

	for {
		e, err := r.NextEntry()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				return
			}
			t.Fatalf("NextEntry error = %v, want io.EOF or ErrNoNextVolume", err)
		}
		if e.Header != nil && e.Header.Name == "FABRICATED.txt" {
			_ = e.Close()
			t.Fatalf("NextEntry returned %q, fabricated from a refused "+
				"member's truncated payload", e.Header.Name)
		}
		_ = e.Close()
	}
}

// memberSpec describes one stored (method 0) RAR5 member. The zero value is an
// ordinary single-block member: notFirst and notLast are negative so that the
// common case needs no fields set.
type memberSpec struct {
	name    string
	content string

	// unpackedSz and packedSz default to len(content). Set them to make the
	// header lie about the size, which is how the bomb and truncation
	// fixtures are built.
	unpackedSz int64
	packedSz   int64

	solid   bool
	isDir   bool
	withCRC bool

	// crcOf overrides what withCRC checksums, defaulting to content. A
	// multi-volume member's last part carries the WHOLE file's CRC32, not
	// just that part's own bytes, so a split fixture must set this to the
	// full reassembled content rather than the tail it actually carries.
	crcOf string

	notFirst bool // clears FirstBlock: this is a continuation block
	notLast  bool // clears LastBlock: the member continues in the next volume

	// badName declares a longer name than the header carries, so
	// ParseFileHeader fails its bounds check while the BLOCK header stays
	// CRC-valid. That is the case the traversal must skip rather than stop on.
	badName bool
}

// rar5Member builds one RAR5 file block followed by its payload.
func rar5Member(t testing.TB, s memberSpec) []byte {
	t.Helper()
	content := []byte(s.content)

	unpacked := s.unpackedSz
	if unpacked == 0 {
		unpacked = int64(len(content))
	}
	packed := s.packedSz
	if packed == 0 {
		packed = int64(len(content))
	}

	var fileFlags uint64
	if s.isDir {
		fileFlags |= FileFlagIsDir
	}
	if s.withCRC {
		fileFlags |= FileFlagHasCRC32
	}

	var f bytes.Buffer
	f.Write(EncodeVint(fileFlags))
	f.Write(EncodeVint(uint64(unpacked)))
	f.Write(EncodeVint(0)) // attributes
	if s.withCRC {
		crcContent := content
		if s.crcOf != "" {
			crcContent = []byte(s.crcOf)
		}
		var crcBuf [4]byte
		binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(crcContent))
		f.Write(crcBuf[:])
	}
	// Compression flags: method lives in bits 7..9, so zero is store (method
	// 0). FileCompSolid is bit 6.
	var compFlags uint64
	if s.solid {
		compFlags |= FileCompSolid
	}
	f.Write(EncodeVint(compFlags))
	f.Write(EncodeVint(0)) // host OS

	name := []byte(s.name)
	if s.badName {
		f.Write(EncodeVint(uint64(len(name) + 16)))
	} else {
		f.Write(EncodeVint(uint64(len(name))))
	}
	f.Write(name)

	blockFlags := uint64(HeaderFlagHasData)
	if s.notFirst {
		blockFlags |= HeaderFlagDataNotFirst
	}
	if s.notLast {
		blockFlags |= HeaderFlagDataNotLast
	}

	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeFile))
	p.Write(EncodeVint(blockFlags))
	p.Write(EncodeVint(uint64(packed)))
	p.Write(f.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(content)
	return out.Bytes()
}

// rar5Archive concatenates the RAR5 signature, an archive header, and each
// member, producing one volume's bytes.
func rar5Archive(t testing.TB, solid bool, members ...[]byte) []byte {
	t.Helper()
	var arc bytes.Buffer
	arc.Write(EncodeVint(HeaderTypeArchive))
	arc.Write(EncodeVint(0))
	var arcFlags uint64
	if solid {
		arcFlags |= ArcFlagSolid
	}
	arc.Write(EncodeVint(arcFlags))

	var out bytes.Buffer
	out.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	out.Write(rar5Block(arc.Bytes()))
	for _, m := range members {
		out.Write(m)
	}
	return out.Bytes()
}

func rarBombArchive(t testing.TB) []byte {
	return rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       "bomb.bin",
		content:    "x",
		unpackedSz: 2 << 30, // 2 GiB declared
		packedSz:   1,       // from 1 byte packed
	}))
}

func archiveWithBadFileHeaderThen(t testing.TB, name, content string) []byte {
	return rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "bad.bin", content: "junkjunk", badName: true}),
		rar5Member(t, memberSpec{name: name, content: content, withCRC: true}),
	)
}

func truncatedThenSolidArchive(t testing.TB) []byte {
	return rar5Archive(t, true,
		// Declares 100 bytes of output but carries 5, so it ends short.
		rar5Member(t, memberSpec{name: "short.bin", content: "short", unpackedSz: 100}),
		rar5Member(t, memberSpec{name: "solid.bin", content: "after", solid: true, withCRC: true}),
	)
}

// malformedArchiveHeaderStream builds a stream whose archive header body
// fails to parse (it declares ArcFlagVolNum without the volume-number vint
// that flag promises follows, though the BLOCK header itself stays
// CRC-valid), followed by a real, well-formed member named plantedName. A
// Reader that does not stop dead at the malformed header can resume scanning
// and hand plantedName back as though nothing happened.
func malformedArchiveHeaderStream(t testing.TB, plantedName string) []byte {
	t.Helper()
	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeArchive))
	p.Write(EncodeVint(0))
	p.Write(EncodeVint(ArcFlagVolNum))

	var archive bytes.Buffer
	archive.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	archive.Write(rar5Block(p.Bytes()))

	planted := rar5Member(t, memberSpec{name: plantedName, content: "payload", withCRC: true})
	return append(archive.Bytes(), planted...)
}

// A malformed archive header ends traversal instead of being skipped: the
// archive header defines archive-wide semantics (including whether the
// archive is solid), so a header this library cannot parse is an
// archive-level problem, not a block to scan past.
func TestMalformedArchiveHeaderEndsTraversal(t *testing.T) {
	stream := malformedArchiveHeaderStream(t, "good.bin")

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err == nil {
		if e != nil {
			_ = e.Close()
		}
		t.Fatalf("NextEntry succeeded past a malformed archive header, "+
			"returning %v; want a non-nil error", e)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("NextEntry returned io.EOF, want the archive header parse error")
	}
	if e != nil {
		t.Fatalf("NextEntry returned a non-nil Entry alongside an error")
	}
	if e != nil && e.Header != nil && e.Header.Name == "good.bin" {
		t.Fatalf("the good member behind the malformed archive header was returned")
	}
}

// TestMalformedArchiveHeaderWrapsSentinels pins the wrap in dispatch's
// HeaderTypeArchive case: a caller must be able to alarm on
// ErrCorruptArchiveHeader specifically, and errors.Is must still reach the
// underlying ErrTruncatedVint through the wrap for callers that want the
// detail.
func TestMalformedArchiveHeaderWrapsSentinels(t *testing.T) {
	stream := malformedArchiveHeaderStream(t, "good.bin")

	r := NewReader(volumesOf(stream))
	_, err := r.NextEntry()
	if err == nil {
		t.Fatal("NextEntry succeeded past a malformed archive header, want an error")
	}
	if !errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("NextEntry error = %v, want errors.Is(err, ErrCorruptArchiveHeader)", err)
	}
	if !errors.Is(err, ErrTruncatedVint) {
		t.Fatalf("NextEntry error = %v, want errors.Is(err, ErrTruncatedVint) to still "+
			"hold through the ErrCorruptArchiveHeader wrap", err)
	}
}

// TestFatalLatchSurvivesSecondCall is the important one: a second NextEntry
// call after a malformed archive header must return the same error and must
// NEVER hand back the well-formed member planted right after it in the
// stream. Asserting only "the second call also errors" is weaker than it
// looks -- a Reader that resumed scanning and stumbled into an unrelated
// parse failure on unrelated bytes would also satisfy that. What actually
// matters is that the planted member is never returned, from any call.
func TestFatalLatchSurvivesSecondCall(t *testing.T) {
	const planted = "should-never-be-returned.bin"
	stream := malformedArchiveHeaderStream(t, planted)

	r := NewReader(volumesOf(stream))

	assertNeverPlanted := func(e *Entry) {
		t.Helper()
		if e == nil {
			return
		}
		defer func() { _ = e.Close() }()
		if e.Header != nil && e.Header.Name == planted {
			t.Fatalf("NextEntry returned the planted member %q after a malformed "+
				"archive header; the latch failed to stop traversal", planted)
		}
	}

	e1, err1 := r.NextEntry()
	assertNeverPlanted(e1)
	if err1 == nil {
		t.Fatal("first NextEntry call succeeded past a malformed archive header")
	}
	if !errors.Is(err1, ErrCorruptArchiveHeader) {
		t.Fatalf("first NextEntry error = %v, want ErrCorruptArchiveHeader", err1)
	}

	e2, err2 := r.NextEntry()
	assertNeverPlanted(e2)
	if e2 != nil {
		t.Fatalf("second NextEntry call returned a non-nil Entry %v after the "+
			"latch, want nil", e2)
	}
	if !errors.Is(err2, ErrCorruptArchiveHeader) {
		t.Fatalf("second NextEntry error = %v, want the same ErrCorruptArchiveHeader "+
			"the first call reported", err2)
	}
	if !errors.Is(err2, err1) && err2.Error() != err1.Error() {
		t.Fatalf("second NextEntry error = %v, want the identical error the first "+
			"call latched (%v)", err2, err1)
	}

	// A third call, for good measure -- the latch must not decay after one repeat.
	e3, err3 := r.NextEntry()
	assertNeverPlanted(e3)
	if !errors.Is(err3, ErrCorruptArchiveHeader) {
		t.Fatalf("third NextEntry error = %v, want ErrCorruptArchiveHeader", err3)
	}
}

// TestResetClearsFatalLatch pins that Reset -- not merely time or further
// calls -- is what clears a latched archive-level failure. A Reader latched
// by a malformed archive header must traverse a fresh, healthy archive
// normally after Reset.
func TestResetClearsFatalLatch(t *testing.T) {
	bad := malformedArchiveHeaderStream(t, "irrelevant.bin")
	r := NewReader(volumesOf(bad))

	if _, err := r.NextEntry(); !errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("NextEntry error = %v, want ErrCorruptArchiveHeader", err)
	}

	good := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "healthy.bin", content: "hello", withCRC: true}),
	)
	r.Reset(volumesOf(good))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after Reset = %v, want a clean traversal", err)
	}
	if e == nil || e.Header == nil || e.Header.Name != "healthy.bin" {
		t.Fatalf("NextEntry after Reset returned %v, want the healthy.bin member", e)
	}
	_ = e.Close()

	if _, err := r.NextEntry(); !errors.Is(err, ErrNoNextVolume) && !errors.Is(err, io.EOF) {
		t.Fatalf("NextEntry at end of the post-Reset archive = %v, want "+
			"ErrNoNextVolume or io.EOF", err)
	}
}

func TestFixtureBuildersRoundTrip(t *testing.T) {
	blk := rar5Member(t, memberSpec{name: "f.bin", content: "hello", withCRC: true})

	h, err := ReadBlockHeader(bytes.NewReader(blk))
	if err != nil {
		t.Fatalf("builder produced an unreadable block: %v", err)
	}
	fh, err := ParseFileHeader(h)
	if err != nil {
		t.Fatalf("builder produced an unparsable file header: %v", err)
	}
	if fh.Name != "f.bin" || fh.UnpackedSize != 5 {
		t.Fatalf("round trip = %q/%d, want f.bin/5", fh.Name, fh.UnpackedSize)
	}
	if !fh.FirstBlock || !fh.LastBlock {
		t.Fatalf("default member should be a single block, got first=%v last=%v",
			fh.FirstBlock, fh.LastBlock)
	}
	if !fh.HasCRC32 || fh.CRC32 != crc32.ChecksumIEEE([]byte("hello")) {
		t.Fatal("builder wrote the wrong CRC32")
	}

	bad := rar5Member(t, memberSpec{name: "bad.bin", content: "junk", badName: true})
	bh, err := ReadBlockHeader(bytes.NewReader(bad))
	if err != nil {
		t.Fatalf("badName fixture must keep a CRC-valid BLOCK header: %v", err)
	}
	if _, err := ParseFileHeader(bh); err == nil {
		t.Fatal("badName fixture must fail ParseFileHeader, or the test it " +
			"backs proves nothing")
	}
}

// TestCRCVerificationIgnoresIsDir pins that FileFlagIsDir cannot switch
// checksum verification off.
//
// entry.go's verifyChecksum gates on e.size == 0 -- the produced size, which
// this type enforces -- rather than on IsDir, which the archive asserts and
// nothing cross-checks. CLAUDE.md names this as a fixed vulnerability:
// gating on IsDir let a crafted archive claiming to be a directory deliver
// arbitrary bytes under a header nothing verified, because the checksum
// check never ran. An entry that produced bytes is verified whatever it
// calls itself.
func TestCRCVerificationIgnoresIsDir(t *testing.T) {
	member := rar5Member(t, memberSpec{
		name:    "d",
		content: "attacker payload",
		isDir:   true,
		withCRC: true,
		crcOf:   "not the actual content", // deliberately wrong CRC32
	})
	archive := rar5Archive(t, false, member)

	r := NewReader(volumesOf(archive))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil && !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("reading an IsDir entry with a wrong CRC32 returned %v", err)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrCRCMismatch) {
		t.Fatalf("Close() on an IsDir entry with a wrong CRC32 = %v, want ErrCRCMismatch", closeErr)
	}
}
