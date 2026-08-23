package rarengine

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// countingReadCloser reports how many bytes were actually read from a volume.
type countingReadCloser struct {
	r io.Reader
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
func (c *countingReadCloser) Close() error { return nil }

// countedVolumesOf is volumesOf (discard_payload_test.go) with each volume
// wrapped in a countingReadCloser, so a test can observe how many bytes the
// traversal actually pulled from the underlying stream. A local variant
// rather than a change to the shared helper, since only this file needs the
// counters.
func countedVolumesOf(parts ...[]byte) (<-chan io.ReadCloser, []*countingReadCloser) {
	ch := make(chan io.ReadCloser, len(parts))
	counters := make([]*countingReadCloser, 0, len(parts))
	for _, p := range parts {
		c := &countingReadCloser{r: bytesReaderFor(p)}
		counters = append(counters, c)
		ch <- c
	}
	close(ch)
	return ch, counters
}

func bytesReaderFor(p []byte) io.Reader { return strings.NewReader(string(p)) }

// Listing an archive's members reads a bounded number of bytes from the
// volume stream. Under the previous design advancing past a member decoded
// and discarded its content unconditionally, which is why gonzbd's
// InspectRar5 decompressed an entire archive just to read filenames.
//
// The byte-count assertion below is a coarse sanity bound: it catches a
// traversal that re-reads a volume, or reads past its declared payload, but
// it does NOT by itself distinguish "skipped" from "decoded and discarded" --
// volume.next() drains whatever a block declares down to zero exactly once
// regardless of which path finishActive took (see volume.go's next(), and
// its comment that the skip amount and a file's PackedSize are "the same
// number by construction"). Decoding a member costs CPU (Huffman/LZ77 work
// and window writes over the member's UNPACKED size), not extra bytes pulled
// from the archive's own stream, so it cannot show up here -- this test
// passes whether or not listing actually decompresses. The name used to
// promise "DoesNotDecompress", a guarantee this assertion cannot enforce;
// that guarantee is pinned directly, by inspecting window state, in
// TestNonSolidAbandonSkipsDecode below.
func TestListingNonSolidArchiveReadsBoundedBytes(t *testing.T) {
	stream := nonSolidArchiveWithCompressedMembers(t)

	ch, counters := countedVolumesOf(stream)
	r := NewReader(ch)
	var names []string
	for {
		e, err := r.NextEntry()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				break
			}
			t.Fatalf("NextEntry: %v", err)
		}
		names = append(names, e.Header.Name)
		// Deliberately never read the member.
	}
	if len(names) < 2 {
		t.Fatalf("listed %d members, want at least 2", len(names))
	}

	// Bound: at most twice the archive's own byte size. The traversal must
	// read every declared byte exactly once on the way to each following
	// header (volume.next()'s unconditional discard), so the true figure is
	// len(stream) almost exactly; 2x leaves headroom for header re-reads
	// without being so loose it would also pass if the whole channel were
	// somehow read twice over.
	got := counters[0].n
	archiveLen := int64(len(stream))
	if got > 2*archiveLen {
		t.Fatalf("listing read %d bytes from a %d-byte archive, want at most %d",
			got, archiveLen, 2*archiveLen)
	}
}

// In a SOLID archive the same skip must still decode, because a successor's
// back-references reach into what the skipped member should have written.
func TestSolidArchiveSkipStillMaintainsWindow(t *testing.T) {
	stream := solidArchiveTwoMembers(t, "one.bin", "two.bin")

	r := NewReader(volumesOf(stream))
	if _, err := r.NextEntry(); err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	// Skip the first member entirely.

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	// The solid successor must either decode correctly (window maintained) or
	// be refused (window marked incomplete). What it must NOT do is decode
	// into plausible-looking wrong content with a nil error.
	_, readErr := io.Copy(io.Discard, second)
	closeErr := second.Close()
	if readErr == nil && closeErr == nil {
		return // window was maintained; correct
	}
	if !errors.Is(closeErr, ErrSolidStreamBroken) && !errors.Is(readErr, ErrCRCMismatch) {
		t.Fatalf("solid successor after a skip: read=%v close=%v; want either "+
			"clean decode or an explicit refusal", readErr, closeErr)
	}
}

// TestNonSolidAbandonSkipsDecode is the mutation-sensitive pin that
// TestListingNonSolidArchiveDoesNotDecompress's byte count cannot be, per the
// comment on that test: a non-solid abandon must never write the member's
// bytes into the window, because that write is exactly the decode work this
// design exists to skip.
//
// This calls the unexported finishActive directly (this file is in package
// rarengine) rather than through a second NextEntry(), because the second
// member's own BeginFile immediately resets the window's write pointer --
// observing finishActive's effect on the FIRST member requires looking
// before that reset happens.
func TestNonSolidAbandonSkipsDecode(t *testing.T) {
	stream := nonSolidArchiveWithCompressedMembers(t)

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if r.solid {
		t.Fatalf("fixture archive header declared solid; this test requires non-solid")
	}
	before := r.win.w

	r.finishActive()
	after := r.win.w

	if after != before {
		t.Fatalf("finishActive wrote %d bytes for member %q into the window "+
			"while abandoning it in a non-solid archive; abandoning a member "+
			"must skip decode entirely", after-before, e.Header.Name)
	}
}

// TestAbandonedEntryCannotReadNextMember is the regression pin for the
// Critical finding: finishActive used to call Entry.Close() only on the solid
// path, leaving a non-solid abandon's Entry with e.src still aliasing
// v.body -- which the next volume.next() call re-points at the FOLLOWING
// member's payload. Reading the abandoned Entry after that point silently
// produced the next member's bytes with a nil error instead of reporting its
// own truncation.
//
// This asserts on the CONTENT the abandoned entry produces, not merely on an
// error being present: the failure mode this pins is wrong bytes with a nil
// error, and an error-only assertion would pass against that bug too (it
// would also pass, uselessly, if e1 simply returned no bytes and no error).
func TestAbandonedEntryCannotReadNextMember(t *testing.T) {
	aContent := strings.Repeat("A", 16)
	bContent := strings.Repeat("B", 16)
	stream := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "A.txt", content: aContent, withCRC: true}),
		rar5Member(t, memberSpec{name: "B.txt", content: bContent, withCRC: true}),
	)

	r := NewReader(volumesOf(stream))
	e1, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if e1.Header.Name != "A.txt" {
		t.Fatalf("first member = %q, want A.txt", e1.Header.Name)
	}

	var first [1]byte
	if _, err := e1.Read(first[:]); err != nil {
		t.Fatalf("reading 1 byte of A.txt: %v", err)
	}

	e2, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if e2.Header.Name != "B.txt" {
		t.Fatalf("second member = %q, want B.txt", e2.Header.Name)
	}

	rest, readErr := io.ReadAll(e1)
	got := string(first[:]) + string(rest)
	if got == aContent+bContent || strings.Contains(got, "B") {
		t.Fatalf("abandoned A.txt produced %q, which contains B.txt's content; "+
			"an abandoned entry must never read through to the next member", got)
	}
	if readErr == nil {
		t.Fatalf("abandoned A.txt Read returned nil error with content %q, "+
			"want a truthful failure", got)
	}

	closeErr := e1.Close()
	if closeErr == nil {
		t.Fatalf("abandoned A.txt Close() = nil, want a non-nil verdict: " +
			"it never produced its declared bytes")
	}
}

func nonSolidArchiveWithCompressedMembers(t testing.TB) []byte {
	t.Helper()
	// Content is large enough, relative to the fixed per-block header
	// overhead, that decoding it would be observably more work than skipping
	// it -- and large enough that TestNonSolidAbandonSkipsDecode's window
	// delta (member length) cannot be confused with pointer noise.
	one := strings.Repeat("first member content, repeated many times. ", 500) // ~22.5 KB
	two := strings.Repeat("second member content, repeated many times. ", 400)
	return rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "one.bin", content: one, withCRC: true}),
		rar5Member(t, memberSpec{name: "two.bin", content: two, withCRC: true}),
	)
}

func solidArchiveTwoMembers(t testing.TB, first, second string) []byte {
	t.Helper()
	return rar5Archive(t, true,
		rar5Member(t, memberSpec{name: first, content: "first member"}),
		rar5Member(t, memberSpec{name: second, content: "second member", solid: true, withCRC: true}),
	)
}
