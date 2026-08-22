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
