package rarengine

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// VerifyPassword answers, without decrypting anything, the question
// SetPasswords can only answer by committing to a decode.
func TestVerifyPassword(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fixture       string
		password      string
		wantVerified  bool
		wantHasCheck  bool
		wantErrorFree bool
	}{
		// Per-file encryption: the check value lives in the file header's
		// encryption record, so the scan stops at the first file header.
		{"file encryption, right password", "rar5_encrypted.rar", "test", true, true, true},
		{"file encryption, wrong password", "rar5_encrypted.rar", "wrong", false, true, true},

		// Header encryption: the archive-level encryption block comes first
		// and answers before any file header is reachable -- those headers
		// are ciphertext.
		{"header encryption, right password", "rar5_encrypted_header.rar", "test", true, true, true},
		{"header encryption, wrong password", "rar5_encrypted_header.rar", "wrong", false, true, true},

		// Nothing to verify is not a failed verification.
		{"unencrypted archive", "rar5_store.rar", "test", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verified, hasCheck, err := VerifyPassword(
				bytes.NewReader(fixtureBytes(t, tc.fixture)), tc.password)
			if tc.wantErrorFree && err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if verified != tc.wantVerified {
				t.Errorf("verified = %v, want %v", verified, tc.wantVerified)
			}
			if hasCheck != tc.wantHasCheck {
				t.Errorf("hasCheckValue = %v, want %v", hasCheck, tc.wantHasCheck)
			}
		})
	}
}

// hasCheckValue is what separates "the password is wrong" from "this archive
// cannot be tested". Collapsing them would reject every archive written
// without a check value, so the distinction is asserted rather than implied.
func TestVerifyPasswordDistinguishesUntestableFromWrong(t *testing.T) {
	wrongVerified, wrongHasCheck, err := VerifyPassword(
		bytes.NewReader(fixtureBytes(t, "rar5_encrypted.rar")), "wrong")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	plainVerified, plainHasCheck, err := VerifyPassword(
		bytes.NewReader(fixtureBytes(t, "rar5_store.rar")), "wrong")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	if wrongVerified || plainVerified {
		t.Fatal("verified must be false in both cases")
	}
	if !wrongHasCheck {
		t.Error("an encrypted archive with a check value must report hasCheckValue=true")
	}
	if plainHasCheck {
		t.Error("an archive with nothing to check must report hasCheckValue=false; " +
			"otherwise it is indistinguishable from a failed verification")
	}
}

// The caller hands over a stream positioned at the start. Requiring it to skip
// the signature first would mean requiring it to know the signature's length,
// which differs between RAR3 and RAR5.
func TestInspectionEntryPointsConsumeTheSignature(t *testing.T) {
	data := fixtureBytes(t, "rar5_store.rar")

	if _, _, err := VerifyPassword(bytes.NewReader(data), "x"); err != nil {
		t.Fatalf("VerifyPassword from the start of the stream: %v", err)
	}
	if _, _, err := VolumeNumber(bytes.NewReader(data)); err != nil {
		t.Fatalf("VolumeNumber from the start of the stream: %v", err)
	}

	// Pre-skipping the signature must NOT be silently tolerated, or a caller
	// doing it would get plausible answers from a mis-framed stream.
	if _, _, err := VolumeNumber(bytes.NewReader(data[8:])); err == nil {
		t.Fatal("VolumeNumber accepted a stream with the signature already " +
			"consumed; that stream is mis-framed and must be reported")
	}
}

// A RAR3 archive is refused by name here as it is in traversal, rather than
// being parsed as RAR5 -- the signatures differ in length as well as content.
func TestInspectionRefusesNonRAR5(t *testing.T) {
	rar3 := []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0x00}
	if _, _, err := VerifyPassword(bytes.NewReader(rar3), "x"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("VerifyPassword on RAR3 = %v, want ErrUnsupportedFormat", err)
	}
	if _, _, err := VolumeNumber(bytes.NewReader(rar3)); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("VolumeNumber on RAR3 = %v, want ErrUnsupportedFormat", err)
	}

	notRAR := bytes.Repeat([]byte{0}, 32)
	if _, _, err := VerifyPassword(bytes.NewReader(notRAR), "x"); !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("VerifyPassword on non-RAR = %v, want ErrUnsupportedFormat", err)
	}
}

// VolumeNumber recovers the ordering of a set whose on-disk names have lost
// it, which is the whole reason it exists.
func TestVolumeNumberRecoversSetOrdering(t *testing.T) {
	for i, name := range []string{
		"rar5_multi.part01.rar", "rar5_multi.part02.rar", "rar5_multi.part03.rar",
		"rar5_multi.part04.rar", "rar5_multi.part05.rar",
	} {
		t.Run(name, func(t *testing.T) {
			index, multi, err := VolumeNumber(bytes.NewReader(fixtureBytes(t, name)))
			if err != nil {
				t.Fatalf("VolumeNumber: %v", err)
			}
			if !multi {
				t.Fatal("multiVolume = false for a member of a split set")
			}
			// RAR5 omits the field on the first volume; reporting that as 0
			// rather than as an absence is what lets a caller sort a set
			// without special-casing its head.
			if index != i {
				t.Fatalf("index = %d, want %d", index, i)
			}
		})
	}
}

func TestVolumeNumberOnSingleArchive(t *testing.T) {
	index, multi, err := VolumeNumber(bytes.NewReader(fixtureBytes(t, "rar5_store.rar")))
	if err != nil {
		t.Fatalf("VolumeNumber: %v", err)
	}
	if multi {
		t.Error("multiVolume = true for a single unsplit archive")
	}
	if index != 0 {
		t.Errorf("index = %d, want 0", index)
	}
}

// Truncation must be reported, not answered. Both entry points walk blocks
// with no volume behind them, so a stream that ends mid-header has to fail
// rather than return a plausible zero.
//
// The 8-byte case is the interesting one: the signature parses, and then the
// stream is simply over. Treating that as "nothing to verify" reported a cut
// archive as needing no password. Real archives never reach it -- an
// unencrypted one answers at its first file header, an empty one at its end
// header -- so only a truncated stream gets there.
func TestInspectionReportsTruncation(t *testing.T) {
	data := fixtureBytes(t, "rar5_multi.part01.rar")
	for _, n := range []int{0, 4, 8, 12, 20} {
		if _, _, err := VolumeNumber(bytes.NewReader(data[:n])); err == nil {
			t.Errorf("VolumeNumber on %d bytes returned no error", n)
		}
		if _, _, err := VerifyPassword(bytes.NewReader(data[:n]), "x"); err == nil {
			t.Errorf("VerifyPassword on %d bytes returned no error", n)
		}
	}
}

// A block's payload must be skipped, or the next header read lands on content.
// This is the same rule volume.next() enforces inside traversal; these entry
// points walk blocks without a volume, so they enforce it themselves.
func TestInspectionSkipsBlockPayloads(t *testing.T) {
	// rar5_comment.rar carries a service block with a payload ahead of its
	// file header, so reaching the file header at all proves the skip.
	verified, hasCheck, err := VerifyPassword(
		bytes.NewReader(fixtureBytes(t, "rar5_comment.rar")), "test")
	if err != nil {
		t.Fatalf("VerifyPassword across a payload-carrying block: %v", err)
	}
	if verified || hasCheck {
		t.Fatalf("unencrypted archive reported verified=%v hasCheckValue=%v",
			verified, hasCheck)
	}
}

// An io.Reader is all that is required: no seeking, no file, no size.
func TestInspectionAcceptsAStreamingReader(t *testing.T) {
	data := fixtureBytes(t, "rar5_multi.part03.rar")
	// iotest-style one-byte-at-a-time reader, wrapped so it exposes only Read.
	index, multi, err := VolumeNumber(struct{ io.Reader }{&byteAtATime{data: data}})
	if err != nil {
		t.Fatalf("VolumeNumber over a one-byte-at-a-time reader: %v", err)
	}
	if !multi || index != 2 {
		t.Fatalf("index=%d multi=%v, want 2 and true", index, multi)
	}
}

type byteAtATime struct {
	data []byte
	off  int
}

func (b *byteAtATime) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = b.data[b.off]
	b.off++
	return 1, nil
}
