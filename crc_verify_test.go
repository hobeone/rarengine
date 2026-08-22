package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

// buildSingleFileRAR5Archive constructs a minimal single-volume, single-file,
// store-method (uncompressed) RAR5 archive in memory, mirroring the
// hand-rolled construction in TestStreamDecompressor_TarStyle. The file
// header's CRC32 field is set to crc32Value with the FileFlagHasCRC32 flag,
// letting callers deliberately mismatch it against content to exercise the
// verification path without needing a corrupted binary fixture.
func buildSingleFileRAR5Archive(t *testing.T, name string, content []byte, crc32Value uint32) *bytes.Buffer {
	t.Helper()
	return buildSingleFileRAR5ArchiveFlags(t, name, content, crc32Value, 0)
}

// buildSingleFileRAR5ArchiveFlags is buildSingleFileRAR5Archive with extra
// file-header flags OR'd in, for exercising flags whose handling is what is
// under test (e.g. FileFlagUnpSizeUnknown).
func buildSingleFileRAR5ArchiveFlags(t *testing.T, name string, content []byte, crc32Value uint32, extraFileFlags uint64) *bytes.Buffer {
	t.Helper()

	// 1. Archive Header
	arcFlagsV := EncodeVint(ArcFlagMultiVol)
	var arcPayload bytes.Buffer
	arcPayload.Write(EncodeVint(HeaderTypeArchive))
	arcPayload.Write(EncodeVint(0))
	arcPayload.Write(arcFlagsV)

	arcSizeV := EncodeVint(uint64(arcPayload.Len()))
	var arcHashed bytes.Buffer
	arcHashed.Write(arcSizeV)
	arcHashed.Write(arcPayload.Bytes())
	arcCrc := crc32.ChecksumIEEE(arcHashed.Bytes())

	var volBuf bytes.Buffer
	volBuf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}) // RAR5 magic
	if err := binary.Write(&volBuf, binary.LittleEndian, arcCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(arcHashed.Bytes())

	// 2. File Header, with FileFlagHasCRC32 set and an explicit (possibly
	// wrong) CRC32 value, store method (compFlags=0 → Method=0).
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(FileFlagHasCRC32 | extraFileFlags)) // flags
	filePayload.Write(EncodeVint(uint64(len(content))))              // unpacked size
	filePayload.Write(EncodeVint(0))                                 // attributes
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32Value)
	filePayload.Write(crcBuf[:])     // CRC32 (gated by FileFlagHasCRC32)
	filePayload.Write(EncodeVint(0)) // compFlags (Method=0, not solid)
	filePayload.Write(EncodeVint(1)) // hostOS
	filePayload.Write(EncodeVint(uint64(len(name))))
	filePayload.WriteString(name)

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagHasData))
	headerPayload.Write(EncodeVint(uint64(len(content))))
	headerPayload.Write(filePayload.Bytes())

	fileSizeV := EncodeVint(uint64(headerPayload.Len()))
	var fileHashed bytes.Buffer
	fileHashed.Write(fileSizeV)
	fileHashed.Write(headerPayload.Bytes())
	fileCrc := crc32.ChecksumIEEE(fileHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, fileCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(fileHashed.Bytes())
	volBuf.Write(content)

	// 3. End Header
	var endPayload bytes.Buffer
	endPayload.Write(EncodeVint(HeaderTypeEnd))
	endPayload.Write(EncodeVint(0))
	endSizeV := EncodeVint(uint64(endPayload.Len()))
	var endHashed bytes.Buffer
	endHashed.Write(endSizeV)
	endHashed.Write(endPayload.Bytes())
	endCrc := crc32.ChecksumIEEE(endHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, endCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(endHashed.Bytes())

	return &volBuf
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
// FileFlagUnpSizeUnknown, the flag ParseFileHeader refuses because it makes
// the declared size -- and so truncation detection -- meaningless.
func rar5FileEntryUnknownSize(name string, content []byte, crc32Value uint32) []byte {
	var fp bytes.Buffer
	fp.Write(EncodeVint(FileFlagHasCRC32 | FileFlagUnpSizeUnknown))
	fp.Write(EncodeVint(uint64(len(content))))
	fp.Write(EncodeVint(0))
	var crcBuf [4]byte
	binary.LittleEndian.PutUint32(crcBuf[:], crc32Value)
	fp.Write(crcBuf[:])
	fp.Write(EncodeVint(0))
	fp.Write(EncodeVint(1))
	fp.Write(EncodeVint(uint64(len(name))))
	fp.WriteString(name)

	var hp bytes.Buffer
	hp.Write(EncodeVint(HeaderTypeFile))
	hp.Write(EncodeVint(HeaderFlagHasData))
	hp.Write(EncodeVint(uint64(len(content))))
	hp.Write(fp.Bytes())

	var out bytes.Buffer
	out.Write(rar5Block(hp.Bytes()))
	out.Write(content)
	return out.Bytes()
}

// TestUnknownUnpackedSizeIsSkippable checks that refusing a file whose
// unpacked size is unknown does not leave its payload in the stream for the
// next header read to land in -- and, stronger than that, that the archive's
// genuine next member is what NextEntry actually reaches. ParseFileHeader
// failing is not surfaced to the caller as a distinguishable error: dispatch
// treats it the same as any other unclaimed block and keeps scanning (see
// reader.go's HeaderTypeFile case), so the only observable property is
// positional recovery, which TestParseFileHeader_RejectsUnknownUnpackedSize
// in header_test.go pairs with to pin that ErrUnpSizeUnknown specifically
// is what ParseFileHeader itself returns.
func TestUnknownUnpackedSizeIsSkippable(t *testing.T) {
	// Distinctive so its presence in the unread remainder would be unambiguous.
	content := []byte("PAYLOAD-MUST-BE-DISCARDED")
	unknownSize := rar5FileEntryUnknownSize("streamed.txt", content, crc32.ChecksumIEEE(content))

	var archive bytes.Buffer
	archive.Write(rar5ArchiveHeader())
	archive.Write(unknownSize)
	archive.Write(rar5FileEntry("real.txt", 4, crc32.ChecksumIEEE([]byte("real")), []byte("real")))
	archive.Write(rar5EndHeader())

	r := NewReader(volumesOf(archive.Bytes()))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if e.Header == nil || e.Header.Name != "real.txt" {
		t.Fatalf("NextEntry returned %v, want real.txt -- the refused member's "+
			"payload must not survive into the next header read", e.Header)
	}
	if got, err := io.ReadAll(e); err != nil || string(got) != "real" {
		t.Fatalf("reading real.txt = %q, %v; want \"real\", nil", got, err)
	}
}
