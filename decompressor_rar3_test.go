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

type bitWriter struct {
	buf []byte
	v   uint64
	n   uint8
}

func (bw *bitWriter) writeBits(val uint32, bits uint8) {
	for i := int(bits) - 1; i >= 0; i-- {
		bit := (val >> uint(i)) & 1
		bw.v = (bw.v << 1) | uint64(bit)
		bw.n++
		if bw.n == 8 {
			bw.buf = append(bw.buf, byte(bw.v))
			bw.v = 0
			bw.n = 0
		}
	}
}

func (bw *bitWriter) flush() {
	if bw.n > 0 {
		bw.buf = append(bw.buf, byte(bw.v<<(8-bw.n)))
		bw.v = 0
		bw.n = 0
	}
}

func TestStreamDecompressor_RAR3_LZ77_ExactDecompression(t *testing.T) {
	// Construct a valid RAR3 LZ77 compressed payload bitstream for "hello rar3"
	expectedText := "hello rar3"

	var bw bitWriter
	// 1. Header: mode bit 0 (LZ77), reuse bit 0 (fresh tables)
	bw.writeBits(0, 1)
	bw.writeBits(0, 1)

	// 2. 20 bit lengths for levelDecoder (BC30 = 20): 4 bits per entry.
	// Symbol 0 (length = 2 bits), Symbol 4 (length = 2 bits), Symbol 16 (length = 2 bits), others = 0
	for i := range bc30 {
		if i == 0 || i == 4 || i == 16 {
			bw.writeBits(2, 4) // 2-bit code
		} else {
			bw.writeBits(0, 4) // 0-bit (unused)
		}
	}
	// levelDecoder: sym 0 -> code '00', sym 4 -> code '01', sym 16 -> code '10'

	// 3. 404 table levels encoded using levelDecoder
	// We want active symbols in main table (299 symbols) to have 4-bit codes (level = 4).
	// Symbols needed: 'h'(104), 'e'(101), 'l'(108), 'o'(111), ' '(32), 'r'(114), 'a'(97), '3'(51), end-of-block (256).
	// Target main table levels:
	targetMain := make([]byte, 299)
	activeSyms := []int{104, 101, 108, 111, 32, 114, 97, 51, 256}
	for _, s := range activeSyms {
		targetMain[s] = 4
	}

	targetAll := make([]byte, 404)
	copy(targetAll[0:299], targetMain)

	// Encode targetAll using sym 0 (code 00) and sym 4 (code 01)
	for i := range targetAll {
		switch targetAll[i] {
		case 0:
			bw.writeBits(0, 2) // sym 0 (code 00)
		case 4:
			bw.writeBits(1, 2) // sym 4 (code 01)
		}
	}

	// 4. Encode literal symbols for "hello rar3" + symbol 256 (EOF)
	// Canonical Canonical Huffman tree for the 9 active symbols (all length 4):
	// Canonical code assignment for sorted symbols:
	// sym 32 (' '): 0000 (0)
	// sym 51 ('3'): 0001 (1)
	// sym 97 ('a'): 0010 (2)
	// sym 101('e'): 0011 (3)
	// sym 104('h'): 0100 (4)
	// sym 108('l'): 0101 (5)
	// sym 111('o'): 0110 (6)
	// sym 114('r'): 0111 (7)
	// sym 256(EOF): 1000 (8)
	codeMap := map[byte]uint32{
		' ': 0, '3': 1, 'a': 2, 'e': 3, 'h': 4, 'l': 5, 'o': 6, 'r': 7,
	}

	for _, ch := range []byte(expectedText) {
		code := codeMap[ch]
		bw.writeBits(code, 4)
	}
	// Write end of block symbol 256 (code 8, 4 bits)
	bw.writeBits(8, 4)

	bw.flush()

	compressedPayload := bw.buf

	// Create custom RAR3 archive with compressed payload
	archiveData := makeRAR3CustomArchive("hello_lz77.txt", compressedPayload, 0, 0, 0, nil, 0x33)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if fh.Name != "hello_lz77.txt" {
		t.Errorf("expected filename 'hello_lz77.txt', got %q", fh.Name)
	}

	buf, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("ReadAll failed for RAR3 LZ77 stream: %v", err)
	}

	if string(buf) != expectedText {
		t.Errorf("expected decompressed output %q, got %q", expectedText, string(buf))
	}
}

func TestStreamDecompressor_RAR3_LZ77_IntegrationFixture(t *testing.T) {
	// Construct a real RAR3 LZ77 archive fixture for "testfile.txt" containing "Testing RAR3 LZ77 Decompression Stream"
	expectedContent := "Testing RAR3 LZ77 Decompression Stream"

	var bw bitWriter
	// 1. Header: mode bit 0 (LZ77), reuse bit 0 (fresh tables)
	bw.writeBits(0, 1)
	bw.writeBits(0, 1)

	// 2. 20 bit lengths for levelDecoder (BC30 = 20)
	for i := range bc30 {
		if i == 0 || i == 5 || i == 16 {
			bw.writeBits(2, 4) // 2-bit code
		} else {
			bw.writeBits(0, 4)
		}
	}

	// 3. 404 table levels encoded using levelDecoder (sym 0=code 00, sym 5=code 01)
	// Active symbols sorted numerically for canonical code assignment
	targetMain := make([]byte, 299)
	activeSyms := []int{32, 51, 55, 65, 68, 76, 82, 83, 84, 90, 97, 99, 101, 103, 105, 109, 110, 111, 112, 114, 115, 116, 256}
	for _, s := range activeSyms {
		targetMain[s] = 5
	}

	targetAll := make([]byte, 404)
	copy(targetAll[0:299], targetMain)

	for i := range targetAll {
		switch targetAll[i] {
		case 0:
			bw.writeBits(0, 2)
		case 5:
			bw.writeBits(1, 2)
		}
	}

	codeMap := make(map[byte]uint32)
	for idx, s := range activeSyms {
		if s < 256 {
			codeMap[byte(s)] = uint32(idx)
		}
	}
	eofCode := uint32(len(activeSyms) - 1)

	for _, ch := range []byte(expectedContent) {
		code := codeMap[ch]
		bw.writeBits(code, 5) // 5-bit codes
	}
	bw.writeBits(eofCode, 5)
	bw.flush()

	// Wrap payload in RAR3 Archive File Header
	archiveData := makeRAR3CustomArchive("testfile.txt", bw.buf, 0, 0, 0, nil, 0x33)

	volumes := make(chan io.ReadCloser, 1)
	volumes <- &mockReadCloser{bytes.NewReader(archiveData)}
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	fh, err := sd.Next()
	if err != nil {
		t.Fatalf("Next() failed: %v", err)
	}

	if sd.Version() != VersionRAR3 {
		t.Errorf("expected version RAR3, got %v", sd.Version())
	}
	if sd.Version().String() != "RAR3" {
		t.Errorf("expected version string 'RAR3', got %q", sd.Version().String())
	}

	if fh.Name != "testfile.txt" {
		t.Errorf("expected filename 'testfile.txt', got %q", fh.Name)
	}

	buf, err := io.ReadAll(sd)
	if err != nil {
		t.Fatalf("ReadAll failed for RAR3 LZ77 integration fixture: %v", err)
	}

	if string(buf) != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, string(buf))
	}
}
