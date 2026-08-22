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
// as content, with Encrypted reported false. PR #44 fixed the same hole for
// RAR3 and it was never applied to RAR5.
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
		unpackedSz: int64(len(content)), // the WHOLE member's output size
		packedSz:   int64(len(first)),   // this part's packed bytes
		notLast:    true,
	}))
	v2 = rar5Archive(t, false, rar5Member(t, memberSpec{
		name:       name,
		content:    second,
		unpackedSz: int64(len(content)),
		packedSz:   int64(len(second)),
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
		name: splitName, content: "aaaa", unpackedSz: 8, packedSz: 4, notLast: true,
	}))
	v2 = rar5Archive(t, false,
		rar5Member(t, memberSpec{
			name: splitName, content: "bbbb", unpackedSz: 8, packedSz: 4,
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

	h, err := ReadBlockHeader(bytes.NewReader(b[8:]))
	if err != nil {
		t.Fatalf("fixture %s: unreadable block header: %v", name, err)
	}
	if h.Type != HeaderTypeArchive {
		t.Fatalf("fixture %s: expected archive header first, got type %d", name, h.Type)
	}
	return b
}
