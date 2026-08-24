package rarengine

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
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

// TestEncryptedHeaderMultiVolume pins that a member spanning a volume boundary
// in a header-encrypted archive decodes.
//
// Every volume of such an archive repeats its own HEAD_CRYPT block in
// plaintext, and each volume is a fresh value whose header decryptor starts
// nil -- openVolume carries nothing forward. dispatch armed decryption from
// that block, but nextVolumePayload's continuation scan skipped it, so the
// rest of volume two's headers were read as plaintext when they were
// ciphertext and the member died partway through with ErrBadHeaderCRC.
//
// The fixture is three volumes produced by `rar a -hpsecret -v9k -m0 -ma5`,
// so the member genuinely crosses two boundaries and the scan runs twice.
// Verification is by SHA-256 against the original rather than by an expected-
// output fixture: the archive's own CRC32 is checked by Close, and an
// independent digest keeps this test from passing on the library agreeing
// with itself.
func TestEncryptedHeaderMultiVolume(t *testing.T) {
	const (
		wantSHA256 = "e1736e7aca9926d24deddc82ab7a68319eeaffae732c48e19cd3b9c278f074b6"
		wantLen    = 24000
	)
	parts := []string{
		"rar5_enchdr_multi.part1.rar",
		"rar5_enchdr_multi.part2.rar",
		"rar5_enchdr_multi.part3.rar",
	}
	ch := make(chan io.ReadCloser, len(parts))
	for _, p := range parts {
		ch <- io.NopCloser(bytes.NewReader(fixtureBytes(t, p)))
	}
	close(ch)

	r := NewReader(ch)
	r.SetPasswords([]string{"secret"})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header.Name != "payload.bin" {
		t.Fatalf("entry = %q, want payload.bin", e.Header.Name)
	}

	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("reading across volumes: %v -- the continuation scan did not "+
			"arm header decryption on the next volume", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
	if len(got) != wantLen {
		t.Fatalf("read %d bytes, want %d", len(got), wantLen)
	}
	if sum := fmt.Sprintf("%x", sha256.Sum256(got)); sum != wantSHA256 {
		t.Fatalf("content SHA-256 = %s, want %s", sum, wantSHA256)
	}
}

// TestEmptyCandidateDoesNotEndThePasswordScan pins that an unusable
// candidate costs itself and nothing else.
//
// VerifyFilePassword reports ErrPasswordRequired for an empty password,
// which says that candidate cannot be checked -- a fact about the
// candidate, not about the archive. Treated as fatal, it ended the scan, so
// a caller passing "" alongside real guesses (the natural way to say "try
// no password first") never reached the guess that would have worked.
//
// Mutation check: return the error instead of continuing in
// resolvePassword and this member is refused with ErrPasswordRequired.
func TestEmptyCandidateDoesNotEndThePasswordScan(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))
	r.SetPasswords([]string{"", encryptedFixturePassword})

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil && !errors.Is(err, io.EOF) &&
		!errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("read after an empty first candidate: %v -- the scan stopped "+
			"at the candidate it could not check", err)
	}
	if err := e.Close(); err != nil && !errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("Close = %v, want nil or ErrChecksumUnsupported", err)
	}
}

// TestHeaderPasswordIsNotLatchedUnverified pins that resolveHeaderPassword
// latches a candidate only when a check value proved it, the same rule
// resolvePassword follows.
//
// A latched password suppresses the scan for every later header. Latching
// one that nothing verified means the archive is committed to whichever
// candidate sorts first, and header decryption then fails with
// ErrBadHeaderCRC -- an archive-level failure, latched on Reader.fatal, so
// the remaining candidates are never reached.
func TestHeaderPasswordIsNotLatchedUnverified(t *testing.T) {
	r := NewReader(encryptedFixtureVolumes(t))
	r.SetPasswords([]string{"wrong-one", encryptedFixturePassword})

	// A crypt header carrying no check value: nothing here can verify a
	// candidate, so the first is used and must NOT be recorded as resolved.
	if _, err := r.resolveHeaderPassword(&cryptHeader{}); err != nil {
		t.Fatalf("resolveHeaderPassword with no check value: %v", err)
	}
	if r.hasResolved {
		t.Fatalf("an unverified candidate was latched as %q; a later header "+
			"carrying a real check value would never be scanned", r.resolved)
	}
}
