package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// encryptedFixturePassword is the password testdata/rar5_encrypted.rar was
// built with. verify_password_test.go pins the same value against the same
// fixture's EncCheck.
const encryptedFixturePassword = "test"

// encryptedFixtureVolumes feeds the single-volume encrypted fixture. It is
// not multi-volume: the splice/decrypt ordering is already pinned by
// encrypted_multivolume_test.go, and this file only exercises candidate
// resolution.
func encryptedFixtureVolumes(t *testing.T) <-chan io.ReadCloser {
	t.Helper()
	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(fixtureBytes(t, "rar5_encrypted.rar"))}
	close(volumes)
	return volumes
}

// The list is tried in order and the right one wins, without the caller
// re-running the archive per candidate.
func TestSetPasswordsResolvesFromCandidateList(t *testing.T) {
	vols := encryptedFixtureVolumes(t) // testdata encrypted RAR5 fixture

	r := NewReader(vols)
	r.SetPasswords([]string{"wrong-one", "wrong-two", encryptedFixturePassword})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	// testdata/rar5_encrypted.rar records its digest as a key-derived MAC
	// (UseMac), the same as the multi-volume fixtures in
	// encrypted_multivolume_test.go, so a successful read is reported as
	// unverifiable rather than as a checksum match.
	if _, err := io.Copy(io.Discard, e); err != nil && !errors.Is(err, io.EOF) &&
		!errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("read encrypted member: %v", err)
	}
	if err := e.Close(); err != nil && !errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("Close = %v, want nil or ErrChecksumUnsupported", err)
	}
}

// No candidate matching is a per-member outcome, not an archive-level error.
func TestNoMatchingPasswordIsATerminalEntry(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))
	r.SetPasswords([]string{"nope"})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry error = %v, want a terminal Entry instead", err)
	}
	if err := e.Close(); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Close = %v, want ErrWrongPassword", err)
	}
}

// An empty candidate list on an encrypted member is "password required", which
// a caller may act on by prompting.
func TestNoPasswordsSuppliedReportsPasswordRequired(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if err := e.Close(); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("Close = %v, want ErrPasswordRequired", err)
	}
}
