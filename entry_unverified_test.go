package rarengine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

// TestBlake2spOnlyMemberReportsUnverifiable is the fixture-backed half of the
// silent path: a real archive written with `rar -htb` carries a BLAKE2sp
// digest and no CRC32 at all.
//
// Before this, verifyChecksum's `!HasCRC32` arm returned nil, so the member
// delivered its bytes and Close reported success with nothing having been
// compared against anything. A caller could not tell that apart from a
// member whose CRC32 matched -- which is the one thing the checksum machinery
// exists to make distinguishable.
//
// Mutation check: restore `if e.size == 0 || !e.cur.HasCRC32 { return nil }`
// and this fails with a nil verdict.
func TestBlake2spOnlyMemberReportsUnverifiable(t *testing.T) {
	data, err := os.ReadFile("testdata/rar5_blake2.rar")
	if err != nil {
		t.Fatal(err)
	}

	r := NewReader(volumesOf(data))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.HasCRC32 {
		t.Fatalf("fixture %q carries a CRC32; it no longer exercises this path",
			e.Header.Name)
	}
	if !e.Header.HasBlake2sp {
		t.Fatalf("fixture %q carries no BLAKE2sp digest either", e.Header.Name)
	}

	got, readErr := io.ReadAll(e)
	closeErr := e.Close()

	// The content is still delivered. Unverifiable is not refused: the caller
	// gets the bytes and the caveat, and decides its own policy. Withholding
	// them would make this a far larger change than making the gap visible.
	if len(got) == 0 {
		t.Fatal("no content delivered; an unverifiable member is reported, not refused")
	}
	verdict := readErr
	if verdict == nil {
		verdict = closeErr
	}
	if !errors.Is(verdict, ErrChecksumUnsupported) {
		t.Fatalf("verdict = %v (read=%v close=%v), want ErrChecksumUnsupported",
			verdict, readErr, closeErr)
	}
}

// A member carrying no digest of any kind is the same verdict. Nothing was
// checked, whether that is because the digest is one we cannot compute or
// because the archive recorded none -- the distinction lives in the message,
// not in what the caller is told about its content.
func TestMemberWithNoDigestReportsUnverifiable(t *testing.T) {
	const content = "0123456789"
	member := rar5Member(t, memberSpec{name: "bare.bin", content: content})

	r := NewReader(volumesOf(rar5Archive(t, false, member)))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}

	got, readErr := io.ReadAll(e)
	closeErr := e.Close()

	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	verdict := readErr
	if verdict == nil {
		verdict = closeErr
	}
	if !errors.Is(verdict, ErrChecksumUnsupported) {
		t.Fatalf("verdict = %v (read=%v close=%v), want ErrChecksumUnsupported",
			verdict, readErr, closeErr)
	}
}

// A member that produced no bytes still completes clean with no digest.
//
// The gate is the produced size, which Entry enforces, and it must stay that
// way: directories and empty files carry no checksum in any RAR5 archive, and
// making them report ErrChecksumUnsupported would fire on every well-formed
// archive that contains a directory. There is nothing to verify, which is not
// the same as having failed to verify something.
func TestZeroLengthMemberWithNoDigestStillCompletesClean(t *testing.T) {
	member := rar5Member(t, memberSpec{name: "dir", isDir: true})

	r := NewReader(volumesOf(rar5Archive(t, false, member)))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil: a member that produced nothing has "+
			"nothing to verify", err)
	}
}

// An unverifiable member does not damage the window, so a solid successor is
// still decoded rather than refused. finishActive excludes
// ErrChecksumUnsupported from the damage set for exactly this reason: the
// member decoded correctly as far as anyone can tell, and its history is
// whatever a solid successor's back-references expect. Making the gap
// observable must not silently convert a whole archive class into damage.
func TestUnverifiableMemberDoesNotDamageTheWindow(t *testing.T) {
	first := rar5Member(t, memberSpec{name: "a.bin", content: "0123456789"})
	second := rar5Member(t, memberSpec{
		name: "b.bin", content: "abcdefghij", withCRC: true, solid: true,
	})

	r := NewReader(volumesOf(rar5Archive(t, true, first, second)))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if _, err := io.ReadAll(e); err != nil && !errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("first member read = %v", err)
	}
	_ = e.Close()

	e, err = r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("solid successor of an unverifiable member = %v; an "+
			"unverifiable digest is not window damage", err)
	}
	if !bytes.Equal(got, []byte("abcdefghij")) {
		t.Fatalf("solid successor content = %q", got)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("solid successor Close = %v", err)
	}
}
