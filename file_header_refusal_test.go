package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
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
// sets headerFlagDataNotFirst), producing a continuation block belonging to
// a member already announced elsewhere.
func memberWithEncVersion(t testing.TB, name, content string, ver uint64, notFirst bool) []byte {
	t.Helper()
	c := []byte(content)

	var f bytes.Buffer
	f.Write(encodeVint(fileFlagHasCRC32))
	f.Write(encodeVint(uint64(len(c))))
	f.Write(encodeVint(0)) // attributes
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(c))
	f.Write(crcBuf[:])
	f.Write(encodeVint(0)) // comp flags: store
	f.Write(encodeVint(0)) // host OS
	f.Write(encodeVint(uint64(len(name))))
	f.Write([]byte(name))

	// Encryption extra record: type 1, version ver, flags 0, 33 bytes of
	// KDF count + salt + IV.
	var rec bytes.Buffer
	rec.Write(encodeVint(1))
	rec.Write(encodeVint(ver))
	rec.Write(encodeVint(0))
	rec.Write(make([]byte, 33))

	var extra bytes.Buffer
	extra.Write(encodeVint(uint64(rec.Len())))
	extra.Write(rec.Bytes())

	blockFlags := uint64(headerFlagHasData | headerFlagHasExtra)
	if notFirst {
		blockFlags |= headerFlagDataNotFirst
	}

	var p bytes.Buffer
	p.Write(encodeVint(headerTypeFile))
	p.Write(encodeVint(blockFlags))
	p.Write(encodeVint(uint64(extra.Len()))) // extra area size
	p.Write(encodeVint(uint64(len(c))))      // data size
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

	h, err := readBlockHeader(bytes.NewReader(blk))
	if err != nil {
		t.Fatalf("builder produced an unreadable block: %v", err)
	}
	fh, err := parseFileHeader(h)
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

// (d) A continuation block (headerFlagDataNotFirst set) whose extra records
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

// (e) window damage from the refusal is recorded: a solid member following
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

// Tests below cover the SAME invariant -- a member whose identity survives a
// late refusal is reported by name, not dropped -- for the two refusals that
// moved from early-in-parseFileHeader positions (right after the flags vint,
// and right after the size vint) into the identity-first validation block
// placed immediately before parseExtraRecords: fileFlagUnpSizeUnknown and a
// negative decoded UnpackedSize. Unlike memberWithEncVersion's trigger (a
// parseExtraRecords failure), these two fire from ordinary field values with
// no extra records at all, so the builders below carry no extra area.

// memberWithUnpSizeUnknown builds a stored member carrying
// fileFlagUnpSizeUnknown: a complete, well-formed header through the name
// field, differing from a valid header ONLY in this flag. notFirst clears
// FirstBlock, producing a continuation block belonging to a member already
// announced elsewhere.
func memberWithUnpSizeUnknown(t testing.TB, name, content string, notFirst bool) []byte {
	t.Helper()
	c := []byte(content)

	var f bytes.Buffer
	f.Write(encodeVint(fileFlagHasCRC32 | fileFlagUnpSizeUnknown))
	f.Write(encodeVint(uint64(len(c)))) // UnpackedSize -- meaningless per the flag, but still decoded
	f.Write(encodeVint(0))              // attributes
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(c))
	f.Write(crcBuf[:])
	f.Write(encodeVint(0)) // comp flags: store
	f.Write(encodeVint(0)) // host OS
	f.Write(encodeVint(uint64(len(name))))
	f.Write([]byte(name))

	blockFlags := uint64(headerFlagHasData)
	if notFirst {
		blockFlags |= headerFlagDataNotFirst
	}

	var p bytes.Buffer
	p.Write(encodeVint(headerTypeFile))
	p.Write(encodeVint(blockFlags))
	p.Write(encodeVint(uint64(len(c))))
	p.Write(f.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(c)
	return out.Bytes()
}

// memberWithNegativeSize builds a stored member whose UnpackedSize vint sets
// the int64 sign bit -- otherwise a complete, well-formed header through the
// name field. notFirst clears FirstBlock the same way memberWithUnpSizeUnknown
// does.
func memberWithNegativeSize(t testing.TB, name, content string, notFirst bool) []byte {
	t.Helper()
	c := []byte(content)

	var f bytes.Buffer
	f.Write(encodeVint(fileFlagHasCRC32))
	f.Write(encodeVint(uint64(1) << 63)) // sets the int64 sign bit
	f.Write(encodeVint(0))               // attributes
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(c))
	f.Write(crcBuf[:])
	f.Write(encodeVint(0)) // comp flags: store
	f.Write(encodeVint(0)) // host OS
	f.Write(encodeVint(uint64(len(name))))
	f.Write([]byte(name))

	blockFlags := uint64(headerFlagHasData)
	if notFirst {
		blockFlags |= headerFlagDataNotFirst
	}

	var p bytes.Buffer
	p.Write(encodeVint(headerTypeFile))
	p.Write(encodeVint(blockFlags))
	p.Write(encodeVint(uint64(len(c))))
	p.Write(f.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(p.Bytes()))
	out.Write(c)
	return out.Bytes()
}

// (a) An UnpSizeUnknown member is refused BY NAME: the FIRST NextEntry call
// returns a non-nil Entry whose Header.Name is the flagged member's name,
// reporting ErrUnpSizeUnknown from both Read and Close. Asserting the FIRST
// entry, never looping to find the name, is deliberate -- a loop would pass
// even if a fabricated entry preceded it.
func TestUnpSizeUnknownMemberRefusedByName(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithUnpSizeUnknown(t, "unknown.bin", "secret", false),
	)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if e == nil || e.Header == nil || e.Header.Name != "unknown.bin" {
		t.Fatalf("NextEntry returned %+v, want Header.Name = unknown.bin", e)
	}

	buf := make([]byte, 16)
	_, readErr := e.Read(buf)
	if !errors.Is(readErr, ErrUnpSizeUnknown) {
		t.Fatalf("Read error = %v, want ErrUnpSizeUnknown", readErr)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrUnpSizeUnknown) {
		t.Fatalf("Close error = %v, want ErrUnpSizeUnknown", closeErr)
	}
}

// (b) A negative-UnpackedSize member is refused BY NAME the same way,
// reporting ErrCorruptFileHeader.
func TestNegativeUnpackedSizeMemberRefusedByName(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithNegativeSize(t, "negative.bin", "secret", false),
	)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if e == nil || e.Header == nil || e.Header.Name != "negative.bin" {
		t.Fatalf("NextEntry returned %+v, want Header.Name = negative.bin", e)
	}

	buf := make([]byte, 16)
	_, readErr := e.Read(buf)
	if !errors.Is(readErr, ErrCorruptFileHeader) {
		t.Fatalf("Read error = %v, want ErrCorruptFileHeader", readErr)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrCorruptFileHeader) {
		t.Fatalf("Close error = %v, want ErrCorruptFileHeader", closeErr)
	}
}

// (c) Traversal continues after an UnpSizeUnknown refusal: the member after
// it is reachable by name with intact content and a clean Close, proving the
// refused member's declared payload was dropped rather than leaking into the
// next header read.
func TestTraversalContinuesAfterRefusedUnpSizeUnknownMember(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithUnpSizeUnknown(t, "unknown.bin", "secret", false),
		rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrUnpSizeUnknown) {
		t.Fatalf("first member verdict = %v, want ErrUnpSizeUnknown", err)
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

// (c) Same as above, for the negative-size refusal.
func TestTraversalContinuesAfterRefusedNegativeSizeMember(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithNegativeSize(t, "negative.bin", "secret", false),
		rar5Member(t, memberSpec{name: "after.bin", content: "visible", withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("first member verdict = %v, want ErrCorruptFileHeader", err)
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

// (d) window damage is recorded for the UnpSizeUnknown refusal: a solid
// member following it must itself be refused, rather than decoded against a
// window missing the refused file's bytes.
func TestSolidMemberAfterRefusedUnpSizeUnknownMemberIsRefused(t *testing.T) {
	stream := rar5Archive(t, true,
		memberWithUnpSizeUnknown(t, "unknown.bin", "secret", false),
		rar5Member(t, memberSpec{name: "solid.bin", content: "after", solid: true, withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrUnpSizeUnknown) {
		t.Fatalf("first member verdict = %v, want ErrUnpSizeUnknown", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if err := second.Close(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}

// (d) Same as above, for the negative-size refusal.
func TestSolidMemberAfterRefusedNegativeSizeMemberIsRefused(t *testing.T) {
	stream := rar5Archive(t, true,
		memberWithNegativeSize(t, "negative.bin", "secret", false),
		rar5Member(t, memberSpec{name: "solid.bin", content: "after", solid: true, withCRC: true}),
	)

	r := NewReader(volumesOf(stream))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if err := first.Close(); !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("first member verdict = %v, want ErrCorruptFileHeader", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if err := second.Close(); !errors.Is(err, ErrSolidStreamBroken) {
		t.Fatalf("solid successor verdict = %v, want ErrSolidStreamBroken", err)
	}
}

// (e) A continuation block (headerFlagDataNotFirst set) carrying
// fileFlagUnpSizeUnknown must still skip silently -- it belongs to a member
// already abandoned and has no identity of its own to report.
func TestUnpSizeUnknownContinuationBlockSkipsSilently(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithUnpSizeUnknown(t, "cont.bin", "secret", true),
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

// (e) Same as above, for a continuation block with a negative declared size.
func TestNegativeSizeContinuationBlockSkipsSilently(t *testing.T) {
	stream := rar5Archive(t, false,
		memberWithNegativeSize(t, "cont.bin", "secret", true),
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

// TestBombRatioSurvivesAnAbsurdPackedSize pins that the expansion guard
// answers the question it was asked, for every declared packed size.
//
// The ratio was computed as 1000*PackedSize, which wraps negative for a
// packed size above MaxInt64/1000. Every member over 1 MB then compared
// greater than a negative number and was refused as a bomb -- the guard
// firing on archives it exists to let through.
//
// Nothing real declares 9 PB packed, which is the point: the value is
// attacker-chosen, and a guard that can be switched into refusing
// everything is as much a defect as one that can be switched off.
func TestBombRatioSurvivesAnAbsurdPackedSize(t *testing.T) {
	member := rar5Member(t, memberSpec{
		name:       "honest.bin",
		content:    "payload",
		unpackedSz: new(int64(2 << 20)),                // over the 1 MB floor the guard applies above
		packedSz:   new(int64(math.MaxInt64/1000 + 1)), // one past where the product wraps
	})
	r := NewReader(volumesOf(rar5Archive(t, false, member)))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, err := io.ReadAll(e); errors.Is(err, ErrRarBombDetected) {
		t.Fatal("a member expanding 2 MiB from an enormous packed size was " +
			"refused as a rar bomb; the ratio wrapped negative")
	}
}
