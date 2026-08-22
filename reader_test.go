package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

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

// A malformed archive header ends traversal instead of being skipped: the
// archive header defines archive-wide semantics (including whether the
// archive is solid), so a header this library cannot parse is an
// archive-level problem, not a block to scan past.
func TestMalformedArchiveHeaderEndsTraversal(t *testing.T) {
	// The block header itself is CRC-valid (rar5Block computes that), but the
	// archive header BODY does not parse: it declares ArcFlagVolNum without
	// the volume-number vint that flag promises follows.
	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeArchive))
	p.Write(EncodeVint(0))
	p.Write(EncodeVint(ArcFlagVolNum))

	var archive bytes.Buffer
	archive.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00})
	archive.Write(rar5Block(p.Bytes()))

	good := rar5Member(t, memberSpec{name: "good.bin", content: "payload", withCRC: true})
	stream := append(archive.Bytes(), good...)

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
