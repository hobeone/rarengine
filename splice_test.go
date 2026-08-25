package rarengine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A member split across two volumes reads as one continuous stream.
func TestMemberSplicesAcrossVolumes(t *testing.T) {
	v1, v2, want := storedMemberSplitAcrossVolumes(t, "split.bin", "hello world")

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// The defect this fixes: a continuation claiming encryption when the first
// block did not had that volume's ciphertext spliced in and delivered verbatim
// as content, with Encrypted reported false. PR #44 fixed the same hole in
// the RAR3 engine since deleted, and the fix was never carried across.
//
// This exercises the mismatch from the other direction from the brief's
// original sketch: the FIRST block declares encryption (a real encrypted
// fixture's volume 1, which rar5Member cannot produce -- Encrypted is set from
// an encryption extra record the builder does not write) and the hand-built
// CONTINUATION does not. The guard compares the two claims symmetrically, so
// this exercises the same check without needing to synthesise that record.
func TestContinuationEncryptionMismatchIsRefused(t *testing.T) {
	v1, v2 := memberWhoseContinuationClaimsEncryption(t, "sneaky.bin")

	r := NewReader(volumesOf(v1, v2))
	r.SetPasswords([]string{"test"})
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if !e.Header.Encrypted {
		t.Fatal("fixture is wrong: the FIRST block must declare encryption")
	}

	_, readErr := io.Copy(io.Discard, e)
	if !errors.Is(readErr, ErrCorruptFileHeader) {
		t.Fatalf("verdict = %v, want ErrCorruptFileHeader -- the continuation "+
			"does not claim encryption the first block did, so the guard "+
			"comparing the two claims must refuse it", readErr)
	}
}

// A member abandoned mid-file leaves continuation blocks on later volumes.
// Reaching the next real member must skip all of them.
func TestAbandonedMultiVolumeMemberIsSkippedToNextEntry(t *testing.T) {
	v1, v2 := splitMemberThenSecondMember(t, "big.bin", "second.bin")

	r := NewReader(volumesOf(v1, v2))
	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if first.Header.Name != "big.bin" {
		t.Fatalf("first member = %q, want big.bin", first.Header.Name)
	}
	// Deliberately read nothing.

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if second.Header.Name != "second.bin" {
		t.Fatalf("second member = %q, want second.bin -- the abandoned "+
			"member's continuation blocks were not skipped", second.Header.Name)
	}
}

// storedMemberSplitAcrossVolumes returns two volumes carrying one member whose
// content is split between them, plus the content it should reassemble to.
func storedMemberSplitAcrossVolumes(t testing.TB, name, content string) (v1, v2 []byte, want string) {
	t.Helper()
	half := len(content) / 2
	first, second := content[:half], content[half:]

	v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       name,
		content:    first,
		unpackedSz: new(int64(len(content))), // the WHOLE member's output size
		packedSz:   new(int64(len(first))),   // this part's packed bytes
		notLast:    true,
	}))
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       name,
		content:    second,
		unpackedSz: new(int64(len(content))),
		packedSz:   new(int64(len(second))),
		notFirst:   true,
		withCRC:    true, // whole-file CRC32 lives on the last part
		crcOf:      content,
	}))
	return v1, v2, content
}

// splitMemberThenSecondMember returns two volumes: the first opens a member
// that continues into the second, where a further member follows it.
func splitMemberThenSecondMember(t testing.TB, splitName, secondName string) (v1, v2 []byte) {
	t.Helper()
	v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: splitName, content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	v2 = rar5Archive(t, false,
		rar5Member(t, memberSpec{
			name: splitName, content: "bbbb", unpackedSz: new(int64(8)), packedSz: new(int64(4)),
			notFirst: true, withCRC: true, crcOf: "aaaabbbb",
		}),
		rar5Member(t, memberSpec{name: secondName, content: "second", withCRC: true}),
	)
	return v1, v2
}

// memberWhoseContinuationClaimsEncryption returns a first volume whose member
// declares encryption and a second whose continuation of it does not.
//
// The guard is symmetric -- it compares the two claims -- so this direction
// exercises the same check as the plaintext-then-encrypted one, and needs no
// hand-built encryption extra record. Reversing it would mean synthesising
// that record; see parseExtraRecords in header.go if that is ever wanted.
func memberWhoseContinuationClaimsEncryption(t testing.TB, name string) (v1, v2 []byte) {
	t.Helper()
	// Volume 1 of the existing encrypted multi-volume (store) fixture. Located
	// with: grep -rn "testdata" encrypted_multivolume_test.go
	v1 = readFixtureVolume(t, "rar5_encrypted_multi_store.part01.rar")
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: name, content: "plaintext-continuation", notFirst: true, withCRC: true,
	}))
	return v1, v2
}

// readFixtureVolume loads one on-disk fixture volume's bytes, verifying it
// parses before handing it back so a broken fixture fails loudly here rather
// than surfacing as a confusing failure in the test that uses it.
//
// It cannot reuse fixtureBytes (filereader_test.go), which is typed to
// *testing.T rather than testing.TB, so it duplicates that one line of file
// loading rather than narrowing every caller here to the concrete type.
func readFixtureVolume(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}

	h, err := readBlockHeader(bytes.NewReader(b[8:]))
	if err != nil {
		t.Fatalf("fixture %s: unreadable block header: %v", name, err)
	}
	if h.Type != headerTypeArchive {
		t.Fatalf("fixture %s: expected archive header first, got type %d", name, h.Type)
	}
	return b
}

// splitMemberThenMissingContinuation returns a first volume whose member
// declares it continues, and a second volume that carries no continuation at
// all -- only a brand-new member.
//
// This is the shape a Usenet download produces when one segment of a
// multi-volume archive is lost: the member in progress can never be completed,
// but every member after it is still intact and independently readable.
func splitMemberThenMissingContinuation(t testing.TB, splitName, survivorName, survivorContent string) (v1, v2 []byte) {
	t.Helper()
	v1 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: splitName, content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name: survivorName, content: survivorContent, withCRC: true,
	}))
	return v1, v2
}

// TestMissingContinuationDoesNotConsumeNextMember pins that a member whose
// continuation never arrives costs exactly itself.
//
// nextVolumePayload reads headers looking for the continuation, so on finding
// a new member instead it has already consumed that member's header from a
// volume that cannot rewind. Returning io.EOF without staging the header let
// the following nextEntry call ask volume.next() for a header, which skips the
// unclaimed payload of the block just read -- so the survivor vanished and the
// archive reported a clean end with a file silently missing.
//
// Asserting the SECOND entry by name is the whole point: a test that merely
// checked the first member reports ErrTruncatedFile passed against the bug.
func TestMissingContinuationDoesNotConsumeNextMember(t *testing.T) {
	const survivor = "I MUST BE REACHABLE"
	v1, v2 := splitMemberThenMissingContinuation(t, "big.bin", "survivor.bin", survivor)

	r := NewReader(volumesOf(v1, v2))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if first.Header.Name != "big.bin" {
		t.Fatalf("first entry = %q, want big.bin", first.Header.Name)
	}
	// Reading it out is what drives nextVolumePayload into the new-member branch.
	if _, err := io.Copy(io.Discard, first); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the split member = %v, want ErrTruncatedFile", err)
	}
	if err := first.Close(); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("Close on the split member = %v, want ErrTruncatedFile", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v -- the member after a missing "+
			"continuation was consumed by the scan that looked for it", err)
	}
	if second.Header.Name != "survivor.bin" {
		t.Fatalf("second entry = %q, want survivor.bin", second.Header.Name)
	}
	got, err := io.ReadAll(second)
	if err != nil {
		t.Fatalf("reading survivor.bin: %v", err)
	}
	if string(got) != survivor {
		t.Fatalf("survivor.bin content = %q, want %q", got, survivor)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("survivor.bin Close = %v, want nil", err)
	}
}

// TestCorruptContinuationHeaderCostsOneMember pins that a member whose
// continuation header does not parse costs that member and no more.
//
// volume.next() has already drained the previous block and drops this one's
// unclaimed payload on the way to the following header, so the stream is
// standing somewhere vouchable and every member behind it is still readable.
// Latching the failure as archive-level ended the entire archive for one
// member's corruption -- and dispatch treats the identical parse failure as a
// per-member outcome, so latching also had the two paths disagreeing about
// the same header.
func TestCorruptContinuationHeaderCostsOneMember(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	v2 := rar5Archive(t, false,
		// badName fails parseFileHeader's name bounds check while the BLOCK
		// header stays CRC-valid, so the continuation scan reaches a header it
		// cannot parse.
		rar5Member(t, memberSpec{name: "split.bin", content: "bbbb", notFirst: true, badName: true}),
		rar5Member(t, memberSpec{name: "after.bin", content: "still here", withCRC: true}),
	)

	r := NewReader(volumesOf(v1, v2))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, first); err == nil {
		t.Fatal("reading the split member succeeded; want its continuation failure")
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v -- one member's corrupt continuation "+
			"ended the whole archive", err)
	}
	if second.Header.Name != "after.bin" {
		t.Fatalf("second entry = %q, want after.bin", second.Header.Name)
	}
	if got, err := io.ReadAll(second); err != nil || string(got) != "still here" {
		t.Fatalf("after.bin = %q, %v; want \"still here\", nil", got, err)
	}
}

// erroringReader yields its bytes together with a non-EOF error on the same
// call, the way a network read that fails mid-buffer does, and reports a clean
// EOF afterwards -- so an implementation that drops the error sees a tidy end
// of stream instead of the failure.
type erroringReader struct {
	data []byte
	err  error
	done bool
}

func (e *erroringReader) Read(p []byte) (int, error) {
	if e.done {
		return 0, io.EOF
	}
	e.done = true
	n := copy(p, e.data)
	return n, e.err
}

// TestSplicePreservesReadErrorAlongsideBytes pins that a read producing bytes
// AND a non-EOF error reports both.
//
// io.Reader does not require an implementation to repeat an error on the next
// call, so returning nil in its place lost the failure outright. io.EOF is the
// deliberate exception: it may be a volume boundary rather than an end, and is
// rediscovered on the following call once the bytes have been delivered.
func TestSplicePreservesReadErrorAlongsideBytes(t *testing.T) {
	wantErr := errors.New("network read failed mid-buffer")
	src := &erroringReader{data: []byte("partial"), err: wantErr}

	e := newEntry(&FileHeader{Name: "x.bin", UnpackedSize: 64, LastBlock: true}, nil)
	s := &multiVolumePayloadReader{r: nil, e: e, src: src}

	buf := make([]byte, 32)
	n, err := s.Read(buf)
	if n != len("partial") {
		t.Fatalf("Read returned n=%d, want %d", n, len("partial"))
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want %v -- the failure was dropped and the "+
			"caller would see a clean stream", err, wantErr)
	}
}

// TestNewMemberWithABadHeaderSurvivesTheContinuationScan pins that a member
// whose header fails to parse is still reported, even when the scan that
// found it was looking for something else.
//
// nextVolumePayload called the exported parseFileHeader, which discards the
// header it built. With no header there is no FirstBlock to test, so a NEW
// member's parse failure was returned as the SPLICED member's failure, and
// the new member was never staged -- the next nextEntry call asked
// volume.next() for a header, which skipped the unclaimed block, and the
// member disappeared from the listing without a name.
//
// The internal parseFileHeader returns the header alongside the error for
// exactly this class of failure. Asserting the refused member by name is the
// point: it is the difference between "refused" and "gone".
func TestNewMemberWithABadHeaderSurvivesTheContinuationScan(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	v2 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "refused.bin", content: "bbbb", badEncVersion: true,
	}))

	r := NewReader(volumesOf(v1, v2))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, first); !errors.Is(err, ErrTruncatedFile) {
		t.Fatalf("reading the split member = %v, want ErrTruncatedFile", err)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v -- the member whose header failed to "+
			"parse was dropped instead of refused", err)
	}
	if second.Header.Name != "refused.bin" {
		t.Fatalf("second entry = %q, want refused.bin", second.Header.Name)
	}
	if _, err := io.ReadAll(second); !errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("reading refused.bin = %v, want ErrUnknownEncryptMethod", err)
	}
}

// TestContinuationForADifferentMemberIsRefused pins that a continuation must
// say it belongs to the member it is being spliced into.
//
// Only the !FirstBlock flag connected the two, so volumes presented out of
// order -- or an archive built to interleave two members -- had another
// file's payload delivered as this one's content, under this one's name and
// with a nil error. The method half of the check matters for the same
// reason: the reader chain is chosen once, from the first block, so a
// continuation switching method fed compressed bytes to a store reader.
func TestContinuationForADifferentMemberIsRefused(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	v2 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "other.bin", content: "bbbb", notFirst: true,
	}))

	r := NewReader(volumesOf(v1, v2))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if !errors.Is(err, ErrCorruptFileHeader) {
		t.Fatalf("reading split.bin = %q, %v; want ErrCorruptFileHeader for a "+
			"continuation naming a different member", got, err)
	}
	if bytes.Contains(got, []byte("bbbb")) {
		t.Fatalf("split.bin was served %q from another member's block", got)
	}
}

// TestNilVolumeStreamIsReportedNotDereferenced pins that a nil element on the
// volumes channel is an error rather than a process kill. It is the caller's
// bug, but openVolume would read the signature straight out of the nil
// interface, and a library cannot answer a bad argument by taking the program
// down with it.
func TestNilVolumeStreamIsReportedNotDereferenced(t *testing.T) {
	volumes := make(chan io.ReadCloser, 1)
	volumes <- nil
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err == nil {
		t.Fatalf("NextEntry returned %v for a nil volume, want an error", e)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("NextEntry reported a clean end of archive for a nil volume")
	}
}
