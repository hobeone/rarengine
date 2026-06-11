package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

func makeRAR3StoreArchive(filename string, content []byte) []byte {
	var buf bytes.Buffer

	// 1. Signature (7 bytes)
	buf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00})

	// 2. Archive Header (MAIN_HEAD, type 0x73)
	// Base size: 2(crc) + 1(type) + 2(flags) + 2(size) = 7
	// Payload size: 2(high_pos_av) + 4(pos_av) = 6
	// Total size = 13
	mainHead := make([]byte, 13)
	mainHead[2] = 0x73                               // type
	mainHead[3] = 0x00                               // flags LSB
	mainHead[4] = 0x00                               // flags MSB
	binary.LittleEndian.PutUint16(mainHead[5:7], 13) // size
	binary.LittleEndian.PutUint16(mainHead[7:9], 0)  // high_pos_av
	binary.LittleEndian.PutUint32(mainHead[9:13], 0) // pos_av

	crcMain := crc32.ChecksumIEEE(mainHead[2:])
	binary.LittleEndian.PutUint16(mainHead[0:2], uint16(crcMain))
	buf.Write(mainHead)

	// 3. File Header (FILE_HEAD, type 0x74)
	// Base size: 7
	// ADD_SIZE: 4
	// Payload size: 4(unp) + 1(os) + 4(crc) + 4(time) + 1(ver) + 1(method) + 2(name_size) + 4(attr) = 21
	// Total header size (including base, ADD_SIZE, and payload) = 7 + 4 + 21 + len(filename) = 32 + len(filename)
	headSize := 32 + len(filename)
	fileHead := make([]byte, headSize)

	fileHead[2] = 0x74 // type
	// flags: 0x8000 (has ADD_SIZE)
	fileHead[3] = 0x00
	fileHead[4] = 0x80

	binary.LittleEndian.PutUint16(fileHead[5:7], uint16(headSize))
	binary.LittleEndian.PutUint32(fileHead[7:11], uint32(len(content))) // ADD_SIZE (PACK_SIZE)

	// File-specific payload
	binary.LittleEndian.PutUint32(fileHead[11:15], uint32(len(content))) // UNP_SIZE
	fileHead[15] = 3                                                     // HOST_OS = Unix

	fileCrc := crc32.ChecksumIEEE(content)
	binary.LittleEndian.PutUint32(fileHead[16:20], fileCrc)
	binary.LittleEndian.PutUint32(fileHead[20:24], 0) // FTIME
	fileHead[24] = 20                                 // UNP_VER
	fileHead[25] = 0x30                               // METHOD = Store
	binary.LittleEndian.PutUint16(fileHead[26:28], uint16(len(filename)))
	binary.LittleEndian.PutUint32(fileHead[28:32], 0o644) // ATTR
	copy(fileHead[32:32+len(filename)], filename)

	crcFile := crc32.ChecksumIEEE(fileHead[2:])
	binary.LittleEndian.PutUint16(fileHead[0:2], uint16(crcFile))
	buf.Write(fileHead)

	// 4. File Content
	buf.Write(content)

	return buf.Bytes()
}

func TestStreamDecompressor_RAR3_Store(t *testing.T) {
	content := []byte("hello rar3 format")
	filename := "hello_rar3.txt"
	archiveData := makeRAR3StoreArchive(filename, content)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != filename {
		t.Errorf("expected filename %q, got %q", filename, fh.Name)
	}
	if fh.UnpackedSize != int64(len(content)) {
		t.Errorf("expected unpacked size %d, got %d", len(content), fh.UnpackedSize)
	}
	if fh.PackedSize != int64(len(content)) {
		t.Errorf("expected packed size %d, got %d", len(content), fh.PackedSize)
	}

	data := make([]byte, len(content))
	_, err = io.ReadFull(sd, data)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("expected content %q, got %q", string(content), string(data))
	}

	_, err = sd.Next()
	if !errors.Is(err, ErrNoNextVolume) {
		t.Errorf("expected ErrNoNextVolume, got %v", err)
	}
}

func makeRAR3CustomArchive(filename string, content []byte, flags uint16, highPack, highUnp uint32, salt []byte, method byte) []byte {
	var buf bytes.Buffer

	// 1. Signature
	buf.Write([]byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00})

	// 2. Archive Header
	mainHead := make([]byte, 13)
	mainHead[2] = 0x73
	binary.LittleEndian.PutUint16(mainHead[5:7], 13)
	crcMain := crc32.ChecksumIEEE(mainHead[2:])
	binary.LittleEndian.PutUint16(mainHead[0:2], uint16(crcMain))
	buf.Write(mainHead)

	// 3. File Header
	payloadSize := 21
	if flags&0x0100 > 0 {
		payloadSize += 8
	}
	payloadSize += len(filename)
	if flags&0x0400 > 0 {
		payloadSize += 8
	}

	headSize := 7 + 4 + payloadSize
	fileHead := make([]byte, headSize)

	fileHead[2] = 0x74
	binary.LittleEndian.PutUint16(fileHead[3:5], flags|0x8000)
	binary.LittleEndian.PutUint16(fileHead[5:7], uint16(headSize))
	binary.LittleEndian.PutUint32(fileHead[7:11], uint32(len(content)))

	binary.LittleEndian.PutUint32(fileHead[11:15], uint32(len(content)))
	fileHead[15] = 3
	binary.LittleEndian.PutUint32(fileHead[20:24], 0)
	fileHead[24] = 20
	fileHead[25] = method
	binary.LittleEndian.PutUint16(fileHead[26:28], uint16(len(filename)))
	binary.LittleEndian.PutUint32(fileHead[28:32], 0o644)

	offset := 32
	if flags&0x0100 > 0 {
		binary.LittleEndian.PutUint32(fileHead[offset:offset+4], highPack)
		binary.LittleEndian.PutUint32(fileHead[offset+4:offset+8], highUnp)
		offset += 8
	}

	copy(fileHead[offset:offset+len(filename)], filename)
	offset += len(filename)

	if flags&0x0400 > 0 {
		copy(fileHead[offset:offset+8], salt)
	}

	crcFile := crc32.ChecksumIEEE(fileHead[2:])
	binary.LittleEndian.PutUint16(fileHead[0:2], uint16(crcFile))
	buf.Write(fileHead)

	// 4. File Content
	buf.Write(content)

	return buf.Bytes()
}

func TestStreamDecompressor_RAR3_HighSize(t *testing.T) {
	content := []byte("hello rar3 high size")
	filename := "hello_rar3_high.txt"
	archiveData := makeRAR3CustomArchive(filename, content, 0x0100, 2, 3, nil, 0x30)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	expectedPackedSize := int64(len(content)) | (2 << 32)
	expectedUnpackedSize := int64(len(content)) | (3 << 32)

	if fh.PackedSize != expectedPackedSize {
		t.Errorf("expected packed size %d, got %d", expectedPackedSize, fh.PackedSize)
	}
	if fh.UnpackedSize != expectedUnpackedSize {
		t.Errorf("expected unpacked size %d, got %d", expectedUnpackedSize, fh.UnpackedSize)
	}
}

func TestStreamDecompressor_RAR3_Salt(t *testing.T) {
	content := []byte("hello rar3 salt")
	filename := "hello_rar3_salt.txt"
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	archiveData := makeRAR3CustomArchive(filename, content, 0x0400, 0, 0, salt, 0x30)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if !bytes.Equal(fh.Salt, salt) {
		t.Errorf("expected salt %v, got %v", salt, fh.Salt)
	}
	if !fh.Encrypted {
		t.Errorf("expected Encrypted to be true since salt is present")
	}
}

func TestStreamDecompressor_RAR3_UnsupportedMethod(t *testing.T) {
	content := []byte("hello rar3 compressed")
	filename := "hello_rar3_comp.txt"
	archiveData := makeRAR3CustomArchive(filename, content, 0, 0, 0, nil, 0x33)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Method != 3 {
		t.Errorf("expected method 3, got %d", fh.Method)
	}

	buf := make([]byte, 10)
	_, err = sd.Read(buf)
	if err == nil {
		t.Fatalf("expected Read to fail for Method 3, but it succeeded")
	}
	if !strings.Contains(err.Error(), "compression method 3 not implemented") {
		t.Errorf("expected 'compression method 3 not implemented' error, got %q", err.Error())
	}
}
