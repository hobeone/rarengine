package rarengine

import (
	"errors"
	"hash/crc32"
	"testing"
)

// Tests for dispatch's headerTypeEncryption error route (reader.go). A
// HEAD_CRYPT block that fails to parse is fatal, not skipped: every header
// after a real crypt header is ciphertext, so an unparsed one leaves the
// rest of the archive unreadable -- there is no degraded-but-useful mode to
// scan forward into. Two causes are classified distinctly: a version this
// library does not implement (the archive may be perfectly valid, just
// written by a newer RAR) versus a genuinely malformed record (the archive
// is damaged). See ErrUnsupportedEncryptionVersion's doc comment.

// TestParseCryptHeader_UnknownVersion_ClassifiesDistinctly is the round-trip
// check required before building the full-stream fixture below: it confirms
// the crypt-header payload fails on the VERSION field specifically, via a
// direct parseCryptHeader call, rather than on some other field that would
// make this fixture indistinguishable from the truncated-payload one.
func TestParseCryptHeader_UnknownVersion_ClassifiesDistinctly(t *testing.T) {
	// Version vint = 1 only. parseCryptHeader reads and rejects the version
	// before it ever looks at flags, KdfCount or salt, so nothing else is
	// needed to reach ErrUnknownEncryptMethod specifically.
	payload := encodeVint(1)
	h := &blockHeader{Type: headerTypeEncryption, Payload: payload}

	_, err := parseCryptHeader(h)
	if !errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("ParseCryptHeader() error = %v, want ErrUnknownEncryptMethod", err)
	}
	if errors.Is(err, ErrCorruptEncryptData) {
		t.Fatalf("ParseCryptHeader() unexpectedly also satisfies ErrCorruptEncryptData; "+
			"fixture is ambiguous between the two failure modes: %v", err)
	}
}

// TestParseCryptHeader_TruncatedPayload_ClassifiesDistinctly is the
// round-trip check for the corruption-side fixture: version 0 (accepted)
// and flags 0, but the record ends before the mandatory KdfCount+salt
// bytes, so parseCryptHeader fails on the length check rather than the
// version check.
func TestParseCryptHeader_TruncatedPayload_ClassifiesDistinctly(t *testing.T) {
	payload := append(encodeVint(0), encodeVint(0)...) // version, flags; no KdfCount/salt
	h := &blockHeader{Type: headerTypeEncryption, Payload: payload}

	_, err := parseCryptHeader(h)
	if !errors.Is(err, ErrCorruptEncryptData) {
		t.Fatalf("ParseCryptHeader() error = %v, want ErrCorruptEncryptData", err)
	}
	if errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("ParseCryptHeader() unexpectedly also satisfies ErrUnknownEncryptMethod; "+
			"fixture is ambiguous between the two failure modes: %v", err)
	}
}

// TestDispatch_CryptHeaderUnknownVersion_IsUnsupportedNotCorrupt is test (a):
// a crypt header declaring a version this library does not implement must
// be classified as ErrUnsupportedEncryptionVersion (with ErrUnknownEncryptMethod
// reachable as the wrapped detail), and must NOT be classified as
// ErrCorruptArchiveHeader -- the archive is not necessarily damaged.
func TestDispatch_CryptHeaderUnknownVersion_IsUnsupportedNotCorrupt(t *testing.T) {
	var archive []byte
	archive = append(archive, rar5ArchiveHeader()...)
	archive = append(archive, rar5BlockDeclaring(headerTypeEncryption, 0, encodeVint(1), false)...)

	r := NewReader(volumesOf(archive))
	e, err := r.NextEntry()
	if e != nil {
		t.Fatalf("NextEntry returned a non-nil Entry alongside a fatal crypt-header error: %v", e)
	}
	if !errors.Is(err, ErrUnsupportedEncryptionVersion) {
		t.Fatalf("NextEntry() error = %v, want errors.Is ErrUnsupportedEncryptionVersion", err)
	}
	if !errors.Is(err, ErrUnknownEncryptMethod) {
		t.Fatalf("NextEntry() error = %v, want errors.Is ErrUnknownEncryptMethod (the wrapped detail)", err)
	}
	if errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("NextEntry() error = %v, unexpectedly also satisfies ErrCorruptArchiveHeader -- "+
			"an unsupported encryption version was misclassified as corruption", err)
	}
}

// TestDispatch_CryptHeaderTruncated_IsCorruptNotUnsupported is test (b): a
// crypt header with a short/truncated payload must be classified as
// ErrCorruptArchiveHeader, and must NOT be classified as
// ErrUnsupportedEncryptionVersion.
func TestDispatch_CryptHeaderTruncated_IsCorruptNotUnsupported(t *testing.T) {
	truncated := append(encodeVint(0), encodeVint(0)...) // version 0, flags 0, no salt

	var archive []byte
	archive = append(archive, rar5ArchiveHeader()...)
	archive = append(archive, rar5BlockDeclaring(headerTypeEncryption, 0, truncated, false)...)

	r := NewReader(volumesOf(archive))
	e, err := r.NextEntry()
	if e != nil {
		t.Fatalf("NextEntry returned a non-nil Entry alongside a fatal crypt-header error: %v", e)
	}
	if !errors.Is(err, ErrCorruptArchiveHeader) {
		t.Fatalf("NextEntry() error = %v, want errors.Is ErrCorruptArchiveHeader", err)
	}
	if errors.Is(err, ErrUnsupportedEncryptionVersion) {
		t.Fatalf("NextEntry() error = %v, unexpectedly also satisfies ErrUnsupportedEncryptionVersion -- "+
			"a corrupt record was misclassified as an unsupported-but-valid archive", err)
	}
}

// TestDispatch_CryptHeaderError_LatchesAndNeverReachesPlantedMember is test
// (c): a malformed crypt header must end traversal for the rest of this
// Reader's life. A complete, CRC-valid file member planted immediately after
// it must never be surfaced -- not on the call that hits the crypt header,
// and not on any later call, which must instead keep returning the same
// error. The planted member's name is distinctive and asserted on directly:
// checking only that the second call "also errors" would pass even if the
// planted member leaked out alongside a spurious second error.
func TestDispatch_CryptHeaderError_LatchesAndNeverReachesPlantedMember(t *testing.T) {
	const wantNeverSeen = "SHOULD_NEVER_BE_REACHABLE.txt"
	planted := rar5FileEntry(wantNeverSeen, 5, crc32.ChecksumIEEE([]byte("owned")), []byte("owned"))

	var archive []byte
	archive = append(archive, rar5ArchiveHeader()...)
	archive = append(archive, rar5BlockDeclaring(headerTypeEncryption, 0, encodeVint(1), false)...)
	archive = append(archive, planted...)
	archive = append(archive, rar5EndHeader()...)

	r := NewReader(volumesOf(archive))

	e1, err1 := r.NextEntry()
	if e1 != nil {
		if e1.Header != nil && e1.Header.Name == wantNeverSeen {
			t.Fatalf("first NextEntry call surfaced the planted member %q past the malformed crypt header", wantNeverSeen)
		}
		t.Fatalf("first NextEntry returned a non-nil Entry alongside a fatal crypt-header error: %v", e1)
	}
	if !errors.Is(err1, ErrUnsupportedEncryptionVersion) {
		t.Fatalf("first NextEntry() error = %v, want errors.Is ErrUnsupportedEncryptionVersion", err1)
	}

	e2, err2 := r.NextEntry()
	if e2 != nil {
		if e2.Header != nil && e2.Header.Name == wantNeverSeen {
			t.Fatalf("second NextEntry call surfaced the planted member %q -- the fatal crypt-header "+
				"error did not latch", wantNeverSeen)
		}
		t.Fatalf("second NextEntry returned a non-nil Entry instead of replaying the latched error: %v", e2)
	}
	if !errors.Is(err2, ErrUnsupportedEncryptionVersion) {
		t.Fatalf("second NextEntry() error = %v, want errors.Is ErrUnsupportedEncryptionVersion (the latched error)", err2)
	}
	if err1 != err2 { //nolint:errorlint // deliberate identity check: NextEntry must replay r.fatal itself
		t.Fatalf("second NextEntry() error = %v, want the SAME error value latched by the first call: %v", err2, err1)
	}
}
