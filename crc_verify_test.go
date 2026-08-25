package rarengine

import (
	"bytes"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// buildSingleFileRAR5Archive constructs a minimal single-volume, single-file,
// store-method (uncompressed) RAR5 archive in memory. The file header's CRC32
// field is set to crc32Value with the fileFlagHasCRC32 flag, letting callers
// deliberately mismatch it against content to exercise the verification path
// without needing a corrupted binary fixture.
func buildSingleFileRAR5Archive(t *testing.T, name string, content []byte, crc32Value uint32) *bytes.Buffer {
	t.Helper()
	return buildSingleFileRAR5ArchiveFlags(t, name, content, crc32Value, 0)
}

// buildSingleFileRAR5ArchiveFlags is buildSingleFileRAR5Archive with extra
// file-header flags OR'd in, for exercising flags whose handling is what is
// under test (e.g. fileFlagUnpSizeUnknown).
//
// It used to write the signature, all three block headers and the file-header
// field order itself -- seventy lines that had to be corrected in step with
// three other copies. It now states only what is peculiar to it: one member,
// between an archive header and an end header.
func buildSingleFileRAR5ArchiveFlags(t *testing.T, name string, content []byte, crc32Value uint32, extraFileFlags uint64) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(rar5ArchiveHeader())
	buf.Write(rar5Member(t, memberSpec{
		name:           name,
		content:        string(content),
		rawCRC:         &crc32Value,
		hostOS:         1,
		extraFileFlags: extraFileFlags,
	}))
	buf.Write(rar5EndHeader())
	return &buf
}

func newSingleVolumeChan(buf *bytes.Buffer) <-chan io.ReadCloser {
	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{buf}
	close(volumes)
	return volumes
}

// readAllAndEOFErr reads e to completion, returning the first non-io.EOF
// error encountered (nil if the stream ended cleanly).
func readAllAndEOFErr(e *Entry) error {
	buf := make([]byte, 4096)
	for {
		_, err := e.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// TestCRCVerification_DefaultDetectsMismatch guards the production bug where
// a RAR volume assembled from incomplete/corrupt download data (wrong
// content bytes, but still a structurally valid, decodable archive) was
// reported as a successful extraction. By default, Read() must surface an
// error wrapping ErrCRCMismatch instead of a clean io.EOF when the
// decompressed content's CRC32 doesn't match the file header's recorded
// CRC32.
func TestCRCVerification_DefaultDetectsMismatch(t *testing.T) {
	content := []byte("world")
	wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF // deliberately wrong
	buf := buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)

	r := NewReader(newSingleVolumeChan(buf))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if err := readAllAndEOFErr(e); !errors.Is(err, ErrCRCMismatch) {
		t.Fatalf("expected ErrCRCMismatch, got %v", err)
	}
}

// TestCRCVerification_DefaultHappyPath confirms verification doesn't false-
// positive on intact data: a correct CRC32 must read through cleanly to
// io.EOF with no error.
func TestCRCVerification_DefaultHappyPath(t *testing.T) {
	content := []byte("world")
	correctCRC := crc32.ChecksumIEEE(content)
	buf := buildSingleFileRAR5Archive(t, "hello.txt", content, correctCRC)

	r := NewReader(newSingleVolumeChan(buf))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	if err := readAllAndEOFErr(e); err != nil {
		t.Fatalf("expected clean EOF, got error: %v", err)
	}
}

// TestCRCVerification_UnconditionalOnMismatch confirms verification can no
// longer be switched off by the caller: SetVerifyCRC does not exist on
// Reader, so a mismatched CRC32 must surface ErrCRCMismatch even from a
// caller that -- under the old API -- would have disabled the check.
func TestCRCVerification_UnconditionalOnMismatch(t *testing.T) {
	content := []byte("world")
	wrongCRC := crc32.ChecksumIEEE(content) ^ 0xFFFFFFFF
	buf := buildSingleFileRAR5Archive(t, "hello.txt", content, wrongCRC)

	r := NewReader(newSingleVolumeChan(buf))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry() failed: %v", err)
	}

	_, _ = io.Copy(io.Discard, e)
	if closeErr := e.Close(); !errors.Is(closeErr, ErrCRCMismatch) {
		t.Fatalf("Close() = %v, want ErrCRCMismatch", closeErr)
	}
}

// rar5FileEntryUnknownSize builds a RAR5 file block declaring
// fileFlagUnpSizeUnknown, the flag parseFileHeader refuses because it makes
// the declared size -- and so truncation detection -- meaningless.
func rar5FileEntryUnknownSize(name string, content []byte, crc32Value uint32) []byte {
	return buildRAR5Member(memberSpec{
		name:           name,
		content:        string(content),
		rawCRC:         &crc32Value,
		hostOS:         1,
		extraFileFlags: fileFlagUnpSizeUnknown,
	})
}

// TestUnknownUnpackedSizeIsRefusedByName checks that a member carrying
// fileFlagUnpSizeUnknown is refused BY NAME (identity-first validation) --
// the FIRST NextEntry call returns a non-nil Entry whose Header.Name is the
// flagged member's name, reporting ErrUnpSizeUnknown from both Read and
// Close -- and, separately, that the refused member's declared payload does
// not leak into the next header read: the archive's genuine next member is
// still reachable by name afterward. Asserting the FIRST entry, never
// looping to find a name, is deliberate: a loop would pass even if a
// fabricated entry preceded it.
//
// This used to assert the opposite -- that the flagged member vanished
// invisibly and NextEntry's first call landed directly on "real.txt" --
// before dispatch had a header identity to refuse by. That assertion
// pinned the OLD (pre identity-first-validation) contract for this specific
// flag and had to change with it; see TestParseFileHeader_RejectsUnknownUnpackedSize
// in header_test.go for the sentinel pin at the parseFileHeader level.
func TestUnknownUnpackedSizeIsRefusedByName(t *testing.T) {
	// Distinctive so its presence in the unread remainder would be unambiguous.
	content := []byte("PAYLOAD-MUST-BE-DISCARDED")
	unknownSize := rar5FileEntryUnknownSize("streamed.txt", content, crc32.ChecksumIEEE(content))

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(unknownSize)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	r := NewReader(volumesOf(archive.Bytes()))

	first, err := r.NextEntry()
	if err != nil {
		t.Fatalf("first NextEntry: %v", err)
	}
	if first == nil || first.Header == nil || first.Header.Name != "streamed.txt" {
		t.Fatalf("first NextEntry returned %+v, want the refused member reported by name (streamed.txt)", first)
	}
	buf := make([]byte, 16)
	if _, readErr := first.Read(buf); !errors.Is(readErr, ErrUnpSizeUnknown) {
		t.Fatalf("first member Read error = %v, want ErrUnpSizeUnknown", readErr)
	}
	if closeErr := first.Close(); !errors.Is(closeErr, ErrUnpSizeUnknown) {
		t.Fatalf("first member Close = %v, want ErrUnpSizeUnknown", closeErr)
	}

	second, err := r.NextEntry()
	if err != nil {
		t.Fatalf("second NextEntry: %v", err)
	}
	if second.Header == nil || second.Header.Name != "real.txt" {
		t.Fatalf("second NextEntry returned %v, want real.txt -- the refused member's "+
			"payload must not survive into the next header read", second.Header)
	}
	if got, err := io.ReadAll(second); err != nil || string(got) != "real" {
		t.Fatalf("reading real.txt = %q, %v; want \"real\", nil", got, err)
	}
	if closeErr := second.Close(); closeErr != nil {
		t.Fatalf("real.txt Close = %v, want nil", closeErr)
	}
}
