package rarengine

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestReadBlockHeader_CorruptCRC(t *testing.T) {
	// A block header has format: [CRC32 (4 bytes)] [size VINT] [payload...]
	// Let's build a size VINT of 2 (representing block size of 2, plus VINT len 1)
	sizeV := EncodeVint(2)
	payload := []byte{HeaderTypeArchive, 0} // archive type, no flags

	var buf bytes.Buffer
	// Bad CRC
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0x12345678)); err != nil {
		t.Fatal(err)
	}
	buf.Write(sizeV)
	buf.Write(payload)

	_, err := ReadBlockHeader(&buf)
	if err != ErrBadHeaderCRC {
		t.Errorf("expected ErrBadHeaderCRC, got %v", err)
	}
}

func TestReadAndParseArchiveHeader(t *testing.T) {
	// Let's build a valid Archive Header block
	// Archive header has type = 1, flags = ArcFlagMultiVol (0x01) | ArcFlagVolNum (0x02)
	// Payload is: flags (VINT), volume number (VINT)
	flagsV := EncodeVint(ArcFlagMultiVol | ArcFlagVolNum)
	volNumV := EncodeVint(4)

	var payload bytes.Buffer
	payload.Write(EncodeVint(HeaderTypeArchive)) // Header type
	payload.Write(EncodeVint(0))                 // Header flags (no extra, no data)
	payload.Write(flagsV)                        // Archive flags
	payload.Write(volNumV)                       // Volume number

	size := payload.Len()
	sizeV := EncodeVint(uint64(size))

	// Hashed portion is: sizeV + payload
	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(payload.Bytes())

	// Compute CRC32
	crc := crc32.ChecksumIEEE(hashed.Bytes())

	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, crc); err != nil {
		t.Fatal(err)
	}
	headerBuf.Write(hashed.Bytes())

	// Read block header
	h, err := ReadBlockHeader(&headerBuf)
	if err != nil {
		t.Fatalf("ReadBlockHeader failed: %v", err)
	}

	if h.Type != HeaderTypeArchive {
		t.Errorf("expected Type %d, got %d", HeaderTypeArchive, h.Type)
	}

	// Parse archive header
	ah, err := ParseArchiveHeader(h)
	if err != nil {
		t.Fatalf("ParseArchiveHeader failed: %v", err)
	}

	if !ah.MultiVolume {
		t.Error("expected MultiVolume to be true")
	}
	if ah.VolumeNumber != 4 {
		t.Errorf("expected VolumeNumber 4, got %d", ah.VolumeNumber)
	}
}

func TestReadAndParseFileHeader(t *testing.T) {
	// Let's build a valid File Header block
	// File flags: FileFlagHasCRC32 (0x04)
	// Unpacked size: 100
	// Attributes: 0
	// CRC32: 0x98765432
	// Comp flags: 0
	// Host OS: 1 (Unix)
	// Name: "test.txt" (len 8)
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(FileFlagHasCRC32)) // File flags
	filePayload.Write(EncodeVint(100))              // Unpacked size
	filePayload.Write(EncodeVint(0))                // Attributes
	if err := binary.Write(&filePayload, binary.LittleEndian, uint32(0x98765432)); err != nil {
		t.Fatal(err)
	} // CRC32
	filePayload.Write(EncodeVint(0))    // Comp flags
	filePayload.Write(EncodeVint(1))    // Host OS: Unix
	filePayload.Write(EncodeVint(8))    // Name len
	filePayload.WriteString("test.txt") // Name

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))    // Header type
	headerPayload.Write(EncodeVint(HeaderFlagHasData)) // Header flags (has data, no extra)
	headerPayload.Write(EncodeVint(50))                // Packed data size (VINT)
	headerPayload.Write(filePayload.Bytes())           // File payload

	size := headerPayload.Len()
	sizeV := EncodeVint(uint64(size))

	// Hashed portion
	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(headerPayload.Bytes())

	crc := crc32.ChecksumIEEE(hashed.Bytes())

	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, crc); err != nil {
		t.Fatal(err)
	}
	headerBuf.Write(hashed.Bytes())

	h, err := ReadBlockHeader(&headerBuf)
	if err != nil {
		t.Fatalf("ReadBlockHeader failed: %v", err)
	}

	if h.DataSize != 50 {
		t.Errorf("expected DataSize 50, got %d", h.DataSize)
	}

	fh, err := ParseFileHeader(h)
	if err != nil {
		t.Fatalf("ParseFileHeader failed: %v", err)
	}

	if fh.Name != "test.txt" {
		t.Errorf("expected Name 'test.txt', got '%s'", fh.Name)
	}
	if fh.UnpackedSize != 100 {
		t.Errorf("expected UnpackedSize 100, got %d", fh.UnpackedSize)
	}
	if !fh.HasCRC32 || fh.CRC32 != 0x98765432 {
		t.Errorf("expected CRC32 0x98765432, got %x (hasCRC: %v)", fh.CRC32, fh.HasCRC32)
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello.txt", "hello.txt"},
		{"/etc/passwd", "etc/passwd"},
		{"../../etc/passwd", "etc/passwd"},
		{"a/b/c/../../../etc/passwd", "etc/passwd"},
		{"a/b/../c", "a/c"},
		{"", ""},
		{".", ""},
		{"..", ""},
		{"/../..", ""},
		{"..\\..\\etc\\passwd", "etc/passwd"},
		{"a\\b\\..\\c", "a/c"},
	}

	for _, tc := range tests {
		got := sanitizePath(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizePath(%q) = %q; expected %q", tc.input, got, tc.expected)
		}
	}
}

func TestFileHeader_ModeAndMTime(t *testing.T) {
	// Build a file header with:
	// File flags: FileFlagHasUnixMtime (0x02) | FileFlagHasCRC32 (0x04)
	// Unpacked size: 50
	// Attributes: 0o755 (493)
	// Unix Mtime: 1700000000 (2023-11-14T22:13:20Z)
	// CRC32: 0x11223344
	// Host OS: 1 (Unix)
	// Name: "exec.sh" (len 7)
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(FileFlagHasUnixMtime | FileFlagHasCRC32)) // flags
	filePayload.Write(EncodeVint(50))                                      // unpacked size
	filePayload.Write(EncodeVint(0o755))                                   // attributes (unix permissions)
	if err := binary.Write(&filePayload, binary.LittleEndian, uint32(1700000000)); err != nil {
		t.Fatal(err)
	} // modification time
	if err := binary.Write(&filePayload, binary.LittleEndian, uint32(0x11223344)); err != nil {
		t.Fatal(err)
	} // CRC32
	filePayload.Write(EncodeVint(0))   // comp flags
	filePayload.Write(EncodeVint(1))   // host OS (Unix)
	filePayload.Write(EncodeVint(7))   // name len
	filePayload.WriteString("exec.sh") // name

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagHasData))
	headerPayload.Write(EncodeVint(20))
	headerPayload.Write(filePayload.Bytes())

	size := headerPayload.Len()
	sizeV := EncodeVint(uint64(size))

	var hashed bytes.Buffer
	hashed.Write(sizeV)
	hashed.Write(headerPayload.Bytes())

	crc := crc32.ChecksumIEEE(hashed.Bytes())

	var headerBuf bytes.Buffer
	if err := binary.Write(&headerBuf, binary.LittleEndian, crc); err != nil {
		t.Fatal(err)
	}
	headerBuf.Write(hashed.Bytes())

	h, err := ReadBlockHeader(&headerBuf)
	if err != nil {
		t.Fatalf("ReadBlockHeader failed: %v", err)
	}

	fh, err := ParseFileHeader(h)
	if err != nil {
		t.Fatalf("ParseFileHeader failed: %v", err)
	}

	if fh.HostOS != 1 {
		t.Errorf("expected HostOS 1, got %d", fh.HostOS)
	}
	if fh.Attributes != 0o755 {
		t.Errorf("expected Attributes 0o755, got %o", fh.Attributes)
	}
	if fh.ModificationTime.Unix() != 1700000000 {
		t.Errorf("expected ModificationTime 1700000000, got %d", fh.ModificationTime.Unix())
	}
	if fh.Mode() != 0o755 {
		t.Errorf("expected Mode 0o755, got %o", fh.Mode())
	}
}
