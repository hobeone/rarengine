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

// encCheckFor builds a real 12-byte per-file password-check value for
// password/salt/kdfCount, using the same PBKDF2 fold verifyEncCheck checks
// against. Only the first 8 bytes are load-bearing; the trailing 4 are the
// SHA-256 validation bytes the format also carries, which this library never
// reads, so they are left zero.
func encCheckFor(password string, salt []byte, kdfCount int) []byte {
	_, pswCheckVal := pbkdf2HmacSha256([]byte(password), salt, 1<<kdfCount)
	check := make([]byte, 12)
	for i := range 32 {
		check[i%8] ^= pswCheckVal[i]
	}
	return check
}

// TestUnverifiedGuessDoesNotSuppressLaterCandidateScan pins that latching only
// happens for a candidate actually verified against a check value.
//
// Member 1 carries no EncCheck, so resolvePassword cannot verify anything and
// falls back to passwords[0] for that member alone. Member 2 does carry a
// check value, and the correct password is third in the list -- if the first
// call had latched its unverified guess, this call would short-circuit on
// hasResolved and return the wrong password without ever running the scan.
//
// This calls resolvePassword directly rather than driving it through
// NextEntry/dispatch: building a two-member archive where the first member
// has no per-file check value and the second does is not something the
// existing fixtures offer, and hand-building one would test the RAR5 header
// encoder as much as this method.
func TestUnverifiedGuessDoesNotSuppressLaterCandidateScan(t *testing.T) {
	salt := bytes.Repeat([]byte{0x11}, 16)
	const kdfCount = 1 // small on purpose; only the fold matters, not the cost
	const rightPassword = "right"

	member1 := &FileHeader{Name: "member1", KdfCount: kdfCount, Salt: salt, EncCheck: nil}
	member2 := &FileHeader{
		Name: "member2", KdfCount: kdfCount, Salt: salt,
		EncCheck: encCheckFor(rightPassword, salt, kdfCount),
	}

	r := NewReader(nil)
	r.SetPasswords([]string{"wrong-one", "wrong-two", rightPassword})

	got1, err := r.resolvePassword(member1)
	if err != nil {
		t.Fatalf("resolvePassword(member1): %v", err)
	}
	if got1 != "wrong-one" {
		t.Fatalf("resolvePassword(member1) = %q, want the unverified default %q",
			got1, "wrong-one")
	}
	if r.hasResolved {
		t.Fatal("hasResolved = true after a member with no check value; " +
			"an unverified guess must not latch")
	}

	got2, err := r.resolvePassword(member2)
	if err != nil {
		t.Fatalf("resolvePassword(member2): %v", err)
	}
	if got2 != rightPassword {
		t.Fatalf("resolvePassword(member2) = %q, want %q -- the candidate scan "+
			"must still run against member2's check value", got2, rightPassword)
	}
	if !r.hasResolved || r.resolved != rightPassword {
		t.Fatalf("after a verified match, resolved = %q hasResolved = %v; "+
			"want %q latched", r.resolved, r.hasResolved, rightPassword)
	}
}
