package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"testing"
)

type mockReadCloser struct {
	io.Reader
}

func (m *mockReadCloser) Close() error { return nil }

func TestStreamDecompressor_TarStyle(t *testing.T) {
	// 1. Archive Header
	arcFlagsV := EncodeVint(ArcFlagMultiVol)
	var arcPayload bytes.Buffer
	arcPayload.Write(EncodeVint(HeaderTypeArchive))
	arcPayload.Write(EncodeVint(0))
	arcPayload.Write(arcFlagsV)

	arcSize := arcPayload.Len()
	arcSizeV := EncodeVint(uint64(arcSize))
	var arcHashed bytes.Buffer
	arcHashed.Write(arcSizeV)
	arcHashed.Write(arcPayload.Bytes())
	arcCrc := crc32.ChecksumIEEE(arcHashed.Bytes())

	var volBuf bytes.Buffer
	volBuf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}) // RAR5 Magic Signature
	if err := binary.Write(&volBuf, binary.LittleEndian, arcCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(arcHashed.Bytes())

	// 2. File Header for "hello.txt"
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(0))
	filePayload.Write(EncodeVint(5))
	filePayload.Write(EncodeVint(0))
	filePayload.Write(EncodeVint(0))
	filePayload.Write(EncodeVint(1))
	filePayload.Write(EncodeVint(9))
	filePayload.WriteString("hello.txt")

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagHasData))
	headerPayload.Write(EncodeVint(5))
	headerPayload.Write(filePayload.Bytes())

	fileSize := headerPayload.Len()
	fileSizeV := EncodeVint(uint64(fileSize))
	var fileHashed bytes.Buffer
	fileHashed.Write(fileSizeV)
	fileHashed.Write(headerPayload.Bytes())
	fileCrc := crc32.ChecksumIEEE(fileHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, fileCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(fileHashed.Bytes())
	volBuf.WriteString("world")

	// 3. End Header
	var endPayload bytes.Buffer
	endPayload.Write(EncodeVint(HeaderTypeEnd))
	endPayload.Write(EncodeVint(0))
	endSize := endPayload.Len()
	endSizeV := EncodeVint(uint64(endSize))
	var endHashed bytes.Buffer
	endHashed.Write(endSizeV)
	endHashed.Write(endPayload.Bytes())
	endCrc := crc32.ChecksumIEEE(endHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, endCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(endHashed.Bytes())

	volumes := make(chan io.ReadCloser, 2)
	volumes <- &mockReadCloser{&volBuf}
	close(volumes)

	sd := NewStreamDecompressor(volumes)

	// Step 1: Advance to next file
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != "hello.txt" {
		t.Errorf("expected 'hello.txt', got '%s'", fh.Name)
	}

	// Step 2: Read data directly from decompressor
	data := make([]byte, 5)
	_, err = io.ReadFull(sd, data)
	if err != nil {
		t.Fatalf("failed to read data: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("expected 'world', got '%s'", string(data))
	}

	// Step 3: Advance again (should hit end of volumes)
	_, err = sd.Next()
	if !errors.Is(err, ErrNoNextVolume) {
		t.Errorf("expected ErrNoNextVolume, got %v", err)
	}
}

func TestStreamDecompressor_RarBomb(t *testing.T) {
	// Create a file header with:
	// UnpackedSize = 2MB (2 * 1024 * 1024)
	// PackedSize = 500 bytes (Ratio > 4000x)
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(0))               // File flags
	filePayload.Write(EncodeVint(2 * 1024 * 1024)) // Unpacked size
	filePayload.Write(EncodeVint(0))               // Attributes
	filePayload.Write(EncodeVint(0))               // Comp flags
	filePayload.Write(EncodeVint(1))               // Host OS: Unix
	filePayload.Write(EncodeVint(8))               // Name len
	filePayload.WriteString("bomb.txt")            // Name

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagHasData))
	headerPayload.Write(EncodeVint(500)) // Packed size
	headerPayload.Write(filePayload.Bytes())

	fileSize := headerPayload.Len()
	fileSizeV := EncodeVint(uint64(fileSize))
	var fileHashed bytes.Buffer
	fileHashed.Write(fileSizeV)
	fileHashed.Write(headerPayload.Bytes())
	fileCrc := crc32.ChecksumIEEE(fileHashed.Bytes())

	var volBuf bytes.Buffer
	volBuf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}) // Magic signature
	if err := binary.Write(&volBuf, binary.LittleEndian, fileCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(fileHashed.Bytes())
	volBuf.Write(make([]byte, 500)) // Dummy packed data

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{&volBuf}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	_, err := sd.Next()
	if !errors.Is(err, ErrRarBombDetected) {
		t.Errorf("expected ErrRarBombDetected, got %v", err)
	}
}

func TestStreamDecompressor_UnknownBlock(t *testing.T) {
	var volBuf bytes.Buffer
	volBuf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}) // Signature

	// 1. Build an Unknown Block (Type = 99)
	// Flags: HeaderFlagHasExtra (0x0001) | HeaderFlagHasData (0x0002)
	// Extra record: size 3, type 10, data 2 bytes: [0xaa, 0xbb]
	var unknownPayload bytes.Buffer
	unknownPayload.Write(EncodeVint(99)) // Header Type 99
	unknownPayload.Write(EncodeVint(HeaderFlagHasExtra | HeaderFlagHasData))
	unknownPayload.Write(EncodeVint(4))  // Extra Area Size (record size 3 + vint len of extra size)
	unknownPayload.Write(EncodeVint(10)) // Data Size (10 bytes of payload to skip)

	// Extra Area:
	// exRecSize = 3 (Type vint + data length)
	// Type = 10 (Unknown record type)
	// Data = [0xaa, 0xbb]
	unknownPayload.Write(EncodeVint(3))
	unknownPayload.Write(EncodeVint(10))
	unknownPayload.Write([]byte{0xaa, 0xbb})

	unkSize := unknownPayload.Len()
	unkSizeV := EncodeVint(uint64(unkSize))

	var unkHashed bytes.Buffer
	unkHashed.Write(unkSizeV)
	unkHashed.Write(unknownPayload.Bytes())
	unkCrc := crc32.ChecksumIEEE(unkHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, unkCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(unkHashed.Bytes())
	volBuf.Write(make([]byte, 10)) // 10 bytes of data area for the unknown block

	// 2. Build a valid File Header (hello.txt, unpacked size 5, method 0, name hello.txt)
	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(0)) // flags
	filePayload.Write(EncodeVint(5)) // unpacked size
	filePayload.Write(EncodeVint(0)) // attributes
	filePayload.Write(EncodeVint(0)) // comp flags
	filePayload.Write(EncodeVint(1)) // host OS
	filePayload.Write(EncodeVint(9)) // name len
	filePayload.WriteString("hello.txt")

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagHasData))
	headerPayload.Write(EncodeVint(5)) // data size
	headerPayload.Write(filePayload.Bytes())

	fileSize := headerPayload.Len()
	fileSizeV := EncodeVint(uint64(fileSize))
	var fileHashed bytes.Buffer
	fileHashed.Write(fileSizeV)
	fileHashed.Write(headerPayload.Bytes())
	fileCrc := crc32.ChecksumIEEE(fileHashed.Bytes())

	if err := binary.Write(&volBuf, binary.LittleEndian, fileCrc); err != nil {
		t.Fatal(err)
	}
	volBuf.Write(fileHashed.Bytes())
	volBuf.WriteString("world")

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{&volBuf}
	close(volumes)

	sd := NewStreamDecompressor(volumes)

	// Step 1: Next() should skip the unknown block (Type 99) and successfully parse "hello.txt"
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != "hello.txt" {
		t.Errorf("expected 'hello.txt', got '%s'", fh.Name)
	}

	data := make([]byte, 5)
	_, err = io.ReadFull(sd, data)
	if err != nil {
		t.Fatalf("failed to read data: %v", err)
	}
	if string(data) != "world" {
		t.Errorf("expected 'world', got '%s'", string(data))
	}
}

func TestMultiVolumePayloadReader_Direct(t *testing.T) {
	sd := NewStreamDecompressor(nil)

	// 1. Test empty buffer p
	mv := &multiVolumePayloadReader{sd: sd, r: bytes.NewReader([]byte("test"))}
	n, err := mv.Read([]byte{})
	if n != 0 || err != nil {
		t.Errorf("expected 0, nil for empty buffer, got %d, %v", n, err)
	}

	// 2. Test normal read from underlying reader
	buf := make([]byte, 4)
	n, err = mv.Read(buf)
	if n != 4 || string(buf) != "test" || err != nil {
		t.Errorf("expected 4 bytes 'test', got %d %q %v", n, buf, err)
	}

	// 3. Test EOF when LastBlock is true
	sd.currHeader = &FileHeader{LastBlock: true}
	mv.r = bytes.NewReader([]byte{}) // EOF
	n, err = mv.Read(buf)
	if n != 0 || err != io.EOF {
		t.Errorf("expected 0, io.EOF, got %d, %v", n, err)
	}

	// 4. Test transition to next volume payload when LastBlock is false
	sd.currHeader = &FileHeader{LastBlock: false}
	volumes := make(chan io.ReadCloser, 1)

	var volBuf bytes.Buffer
	volBuf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}) // Signature

	var filePayload bytes.Buffer
	filePayload.Write(EncodeVint(0)) // flags
	filePayload.Write(EncodeVint(5)) // unpacked size
	filePayload.Write(EncodeVint(0)) // attributes
	filePayload.Write(EncodeVint(0)) // comp flags
	filePayload.Write(EncodeVint(1)) // host OS
	filePayload.Write(EncodeVint(9)) // name len
	filePayload.WriteString("hello.txt")

	var headerPayload bytes.Buffer
	headerPayload.Write(EncodeVint(HeaderTypeFile))
	headerPayload.Write(EncodeVint(HeaderFlagDataNotFirst | HeaderFlagHasData)) // FirstBlock = false, HasData = true
	headerPayload.Write(EncodeVint(4))                                          // data size (PackedSize = 4)
	headerPayload.Write(filePayload.Bytes())

	fileSize := headerPayload.Len()
	fileSizeV := EncodeVint(uint64(fileSize))
	var fileHashed bytes.Buffer
	fileHashed.Write(fileSizeV)
	fileHashed.Write(headerPayload.Bytes())
	fileCrc := crc32.ChecksumIEEE(fileHashed.Bytes())

	_ = binary.Write(&volBuf, binary.LittleEndian, fileCrc)
	volBuf.Write(fileHashed.Bytes())
	volBuf.WriteString("next") // 4 bytes of continuation payload

	volumes <- &mockReadCloser{&volBuf}
	close(volumes)

	sd.volumes = volumes
	mv.r = bytes.NewReader([]byte{}) // trigger transition

	buf = make([]byte, 4)
	n, err = mv.Read(buf)
	if n != 4 || string(buf) != "next" || err != nil {
		t.Errorf("expected 4 bytes 'next' from next volume, got %d %q %v", n, buf, err)
	}
}
