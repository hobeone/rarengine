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
	binary.Write(&volBuf, binary.LittleEndian, arcCrc)
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

	binary.Write(&volBuf, binary.LittleEndian, fileCrc)
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

	binary.Write(&volBuf, binary.LittleEndian, endCrc)
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
