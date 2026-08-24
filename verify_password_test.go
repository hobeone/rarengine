package rarengine

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// cryptHeaderFromFixture opens a header-encrypted RAR5 fixture and reads
// block headers, in the same order Reader.dispatch does, until it finds the
// HEAD_CRYPT (archive header encryption) block, then returns its parsed
// CryptHeader.
func cryptHeaderFromFixture(t *testing.T, name string) *cryptHeader {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := openVolume(f); err != nil {
		t.Fatalf("openVolume: %v", err)
	}

	for {
		h, err := readBlockHeader(f)
		if err != nil {
			if err == io.EOF { //nolint:errorlint // sentinel from ReadBlockHeader
				t.Fatalf("no HEAD_CRYPT block found in %s", name)
			}
			t.Fatalf("ReadBlockHeader: %v", err)
		}
		if h.Type == headerTypeEncryption {
			ch, err := parseCryptHeader(h)
			if err != nil {
				t.Fatalf("ParseCryptHeader: %v", err)
			}
			return ch
		}
		if h.DataSize > 0 {
			if _, err := io.Copy(io.Discard, io.LimitReader(f, h.DataSize)); err != nil {
				t.Fatalf("skipping block data: %v", err)
			}
		}
	}
}

// fileHeaderFromFixture opens a file-content-encrypted RAR5 fixture (headers
// themselves plaintext) and returns the parsed FileHeader for the first file
// entry, via the public Next() API. Next() succeeds regardless of whether a
// password was set -- the per-file password check only happens lazily when
// Read() is first called on the file's content -- so no password needs to be
// supplied here.
func fileHeaderFromFixture(t *testing.T, name string) *FileHeader {
	t.Helper()

	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	return e.Header
}

func TestVerifyPassword_HeaderEncrypted(t *testing.T) {
	ch := cryptHeaderFromFixture(t, "rar5_encrypted_header.rar")

	tests := []struct {
		name         string
		password     string
		wantVerified bool
	}{
		{"correct password", "test", true},
		{"wrong password", "definitely-wrong", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verified, hasCheckValue, err := verifyCryptHeaderPassword(ch, tc.password)
			if err != nil {
				t.Fatalf("VerifyPassword() unexpected error: %v", err)
			}
			if !hasCheckValue {
				t.Fatalf("VerifyPassword() hasCheckValue = false, want true for fixture with a stored check value")
			}
			if verified != tc.wantVerified {
				t.Errorf("VerifyPassword() verified = %v, want %v", verified, tc.wantVerified)
			}
		})
	}
}

func TestVerifyPassword_NoCheckValue(t *testing.T) {
	ch := &cryptHeader{KdfCount: 0, Salt: make([]byte, 16)}

	verified, hasCheckValue, err := verifyCryptHeaderPassword(ch, "anything")
	if err != nil {
		t.Fatalf("VerifyPassword() unexpected error: %v", err)
	}
	if hasCheckValue {
		t.Fatalf("VerifyPassword() hasCheckValue = true, want false when CheckValue is nil")
	}
	if verified {
		t.Fatalf("VerifyPassword() verified = true, want false when there is no check value to verify against")
	}
}

func TestVerifyFilePassword_ContentEncrypted(t *testing.T) {
	fh := fileHeaderFromFixture(t, "rar5_encrypted.rar")

	tests := []struct {
		name         string
		password     string
		wantVerified bool
	}{
		{"correct password", "test", true},
		{"wrong password", "definitely-wrong", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verified, hasCheckValue, err := verifyFileHeaderPassword(fh, tc.password)
			if err != nil {
				t.Fatalf("VerifyFilePassword() unexpected error: %v", err)
			}
			if !hasCheckValue {
				t.Fatalf("VerifyFilePassword() hasCheckValue = false, want true for fixture with a stored check value")
			}
			if verified != tc.wantVerified {
				t.Errorf("VerifyFilePassword() verified = %v, want %v", verified, tc.wantVerified)
			}
		})
	}
}

func TestVerifyFilePassword_NoCheckValue(t *testing.T) {
	fh := &FileHeader{KdfCount: 0, Salt: make([]byte, 16)}

	verified, hasCheckValue, err := verifyFileHeaderPassword(fh, "anything")
	if err != nil {
		t.Fatalf("VerifyFilePassword() unexpected error: %v", err)
	}
	if hasCheckValue {
		t.Fatalf("VerifyFilePassword() hasCheckValue = true, want false when EncCheck is nil")
	}
	if verified {
		t.Fatalf("VerifyFilePassword() verified = true, want false when there is no check value to verify against")
	}
}
