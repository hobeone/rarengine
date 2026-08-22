package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// Tests for the invariant that a file header failing to parse AFTER its name
// and sizes are already decoded (i.e. a failure inside parseExtraRecords)
// must be reported to the caller as a refused member, not dropped from the
// listing with no trace. Every earlier failure -- before the name is known --
// still has nothing to report and is skipped exactly as before; see
// TestUnparsableFileHeaderDoesNotEndTraversal for that case.
//
// memberWithEncVersion produces the concrete, empirically-verified trigger:
// an encryption extra record declaring a version other than 0 fails inside
// parseEncryptionRecord, the last field parseFileHeader decodes, well after
// the name.

// memberWithEncVersion builds a stored member carrying an encryption extra
// record declaring encryption version ver. notFirst clears FirstBlock (i.e.
// sets HeaderFlagDataNotFirst), producing a continuation block belonging to
// a member already announced elsewhere.
func memberWithEncVersion(t testing.TB, name, content string, ver uint64, notFirst bool) []byte {
	t.Helper()
	c := []byte(content)

	var f bytes.Buffer
	f.Write(EncodeVint(FileFlagHasCRC32))
	f.Write(EncodeVint(uint64(len(c))))
	f.Write(EncodeVint(0)) // attributes
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(c))
	f.Write(crcBuf[:])
	f.Write(EncodeVint(0)) // comp flags: store
	f.Write(EncodeVint(0)) // host OS
	f.Write(EncodeVint(uint64(len(name))))
	f.Write([]byte(name))

	// Encryption extra record: type 1, version ver, flags 0, 33 bytes of
	// KDF count + salt + IV.
	var rec bytes.Buffer
	rec.Write(EncodeVint(1))
	rec.Write(EncodeVint(ver))
	rec.Write(EncodeVint(0))
	rec.Write(make([]byte, 33))

	var extra bytes.Buffer
	extra.Write(EncodeVint(uint64(rec.Len())))
	extra.Write(rec.Bytes())

	blockFlags := uint64(HeaderFlagHasData | HeaderFlagHasExtra)
	if notFirst {
		blockFlags |= HeaderFlagDataNotFirst
	}

	var p bytes.Buffer
	p.Write(EncodeVint(HeaderTypeFile))
	p.Write(EncodeVint(blockFlags))
	p.Write(EncodeVint(uint64(extra.Len()))) // extra area size
	p.Write(EncodeVint(uint64(len(c))))      // data size
	p.Write(f.Bytes())
	p.Write(extra.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(c)
	return out.Bytes()
}

// (a) Fixture round-trip guard: ver=0 with this exact geometry must parse
// successfully and yield Encrypted=true. Without this, a geometry mistake in
// memberWithEncVersion would make every test below pass for the wrong
// reason -- see TestFixtureBuildersRoundTrip for the established pattern.
func TestMemberWithEncVersionRoundTrip(t *testing.T) {
	blk := memberWithEncVersion(t, "enc0.bin", "hello", 0, false)

	h, err := ReadBlockHeader(bytes.NewReader(blk))
	if err != nil {
		t.Fatalf("builder produced an unreadable block: %v", err)
	}
	fh, err := ParseFileHeader(h)
	if err != nil {
		t.Fatalf("builder produced an unparsable file header with ver=0: %v", err)
	}
	if fh.Name != "enc0.bin" {
		t.Fatalf("round trip name = %q, want enc0.bin", fh.Name)
	}
	if !fh.Encrypted {
		t.Fatalf("round trip Encrypted = false, want true for a ver=0 encryption record")
	}
}

// (b) A member whose extra records fail to parse AFTER its name is known is
// refused BY NAME: the first NextEntry call must return a non-nil Entry
// whose Header.Name is the member's name, and whose Read and Close both
// report ErrUnknownEncryptMethod. Asserting the FIRST entry, not looping to
// find it, is deliberate -- a test that loops until it finds the name would
// pass even if a fabricated entry preceded it.
func TestRefusedExtraRecordMemberReportedByName(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithEncVersion(t, "bad.enc", "secret", 1, false),
	)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if e == nil {
		t.Fatal("NextEntry returned a nil Entry, want the refused member reported by name")
	}
	if e.Header == nil || e.Header.Name != "bad.enc" {
		t.Fatalf("NextEntry returned %+v, want Header.Name = bad.enc", e.Header)
	}

	buf := make([]byte, 16)
	_, readErr := e.Read(buf)
	if !errors.Is(readErr, ErrUnknownEncryptMethod) {
		t.Fatalf("Read error = %v, want ErrUnknownEncryptMethod", readErr)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrUnknownEncryptMethod) {
		t.Fatalf("Close error = %v, want ErrUnknownEncryptMethod", closeErr)
	}
}

// (c) Traversal continues correctly after the refusal: the member after the
// refused one is still reachable by name, with its content intact, proving
// the refused member's declared payload was dropped rather than leaking into
// the next header read.
func TestTraversalContinuesAfterRefusedExtraRecordMember(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithEncVersion(t, "bad.enc", "secret", 1, false),
		rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("first member verdict = %v, want ErrUnknownEncryptMethod", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if second.Header == nil || second.Header.Name != "after.bin" {
		t.Fatalf("second NextEntry returned %+v, want after.bin", second.Header)
	}
	content, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("reading after.bin: %v", err)
	}
	if string(content) != "visible" {
		t.Fatalf("after.bin content = %q, want %q", content, "visible")
	}
	if err := second.Close(); err != nil {
		t.Fatalf("after.bin Close = %v, want nil", err)
	}
}

// (d) A continuation block (HeaderFlagDataNotFirst set) whose extra records
// fail to parse must still skip silently, exactly like the FirstBlock case
// already covered by TestUnparsableFileHeaderDoesNotEndTraversal -- it
// belongs to a member already abandoned and has no identity of its own to
// report.
func TestRefusedExtraRecordContinuationBlockSkipsSilently(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithEncVersion(t, "cont.enc", "secret", 1, true),
		rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
	)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want the continuation block skipped silently", err)
	}
	if e == nil || e.Header == nil || e.Header.Name != "after.bin" {
		t.Fatalf("NextEntry returned %+v, want after.bin (continuation block must not surface)", e)
	}
	_ = e.Close()
}

// (e) Window damage from the refusal is recorded: a solid member following
// the refused one must be refused too, rather than decoded against a window
// missing the refused file's bytes. Mirrors TestSolidMemberAfterDamageIsRefused.
func TestSolidMemberAfterRefusedExtraRecordMemberIsRefused(t *testing.T) {
	stream := rar5Archive(t, true,
		memberWithEncVersion(t, "bad.enc", "secret", 1, false),
		rar5Member(t, memberSpec{name: "solid.bin", content: "after", solid: true, withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("first member verdict = %v, want ErrUnknownEncryptMethod", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if err := second.Close(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}
