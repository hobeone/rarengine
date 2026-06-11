package rarengine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
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
