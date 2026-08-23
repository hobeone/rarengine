package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// TestCutInsideAMembersPayloadIsNotStitchedOver pins that a volume ending
// inside the packed bytes a member declared fails that member, rather than
// being joined to whatever the next volume holds.
//
// io.LimitedReader reports io.EOF whether it delivered its whole count or
// the source ran out under it, so the splice could not tell a volume
// boundary from a cut. It advanced either way: the missing bytes were
// stitched over with the next volume's continuation and the member completed
// -- claiming success for content it never received, or failing its CRC with
// an error that names the wrong cause.
//
// Mutation check: drop the bodyShort() test from
// multiVolumePayloadReader.Read and this member reads to completion.
func TestCutInsideAMembersPayloadIsNotStitchedOver(t *testing.T) {
	// The header declares 10 packed bytes; the volume carries 4.
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: 14, packedSz: 10, notLast: true,
	}))
	v2 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "bbbbbbbbbb", notFirst: true,
	}))

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reading a member cut mid-payload = %q, %v; want io.ErrUnexpectedEOF", got, err)
	}
	if err := e.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Close = %v, want the same verdict io.ErrUnexpectedEOF", err)
	}
}

// TestDamagedSetDoesNotEndAsACleanArchive pins that a cut somewhere the
// traversal cannot vouch for is reported when the volumes run out, instead
// of the io.EOF that means the archive is over.
//
// The scan deliberately continues past the cut -- the members beyond it are
// still readable, and a set arriving with a part missing is ordinary. What
// it must not do is then report a clean end, because a caller looping until
// io.EOF would take a set with a hole in it for a complete one.
//
// Mutation check: stop assigning Reader.damaged and the final NextEntry
// returns io.EOF with the missing member unaccounted for.
func TestDamagedSetDoesNotEndAsACleanArchive(t *testing.T) {
	// An end header claiming a payload the volume does not carry: the cut is
	// in a block that belongs to no member, so nothing else reports it.
	var vol bytes.Buffer
	vol.Write(rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "present.bin", content: "here", withCRC: true,
	})))
	vol.Write(rar5BlockDeclaring(HeaderTypeEnd, 32, nil, true))

	r := NewReader(volumesOf(vol.Bytes()))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if got, err := io.ReadAll(e); err != nil || string(got) != "here" {
		t.Fatalf("present.bin = %q, %v; want \"here\", nil", got, err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("present.bin Close = %v, want nil", err)
	}

	_, err = r.NextEntry()
	if errors.Is(err, io.EOF) {
		t.Fatal("NextEntry reported a clean end of archive for a set that " +
			"ended inside a block's declared payload")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("NextEntry = %v, want io.ErrUnexpectedEOF", err)
	}
}
