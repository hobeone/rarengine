package rarengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// A block that declares payload, followed by a real block. next() must reach
// the second block without the caller discarding anything: the whole point of
// the type is that skipping is not a caller obligation.
func TestVolumeNextSkipsUnclaimedPayload(t *testing.T) {
	// An archive header declaring 20 bytes of payload, with a complete,
	// CRC-valid file block planted inside that payload. A traversal that
	// fails to skip parses the planted block as the next header.
	planted := rar5Block(func() []byte {
		var p bytes.Buffer
		p.Write(EncodeVint(HeaderTypeFile))
		p.Write(EncodeVint(0))
		return p.Bytes()
	}())
	archive := rar5BlockDeclaring(HeaderTypeArchive, len(planted), nil, true)

	real := rar5Block(func() []byte {
		var p bytes.Buffer
		p.Write(EncodeVint(HeaderTypeEnd))
		p.Write(EncodeVint(0))
		return p.Bytes()
	}())

	stream := append(append(append([]byte{}, archive...), planted...), real...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}

	h, err := v.next()
	if err != nil {
		t.Fatalf("first next(): %v", err)
	}
	if h.Type != HeaderTypeArchive {
		t.Fatalf("first block type = %d, want HeaderTypeArchive", h.Type)
	}

	h, err = v.next()
	if err != nil {
		t.Fatalf("second next(): %v", err)
	}
	if h.Type != HeaderTypeEnd {
		t.Fatalf("second block type = %d, want HeaderTypeEnd (the planted "+
			"file block was parsed out of the first block's payload)", h.Type)
	}
}

// payload() must not reach past the block's declared size, so a decoder
// cannot consume the following header.
func TestVolumePayloadIsBoundedByDataSize(t *testing.T) {
	const declared = 4
	trailing := []byte("SHOULD-NOT-BE-READABLE")
	blk := rar5BlockDeclaring(HeaderTypeFile, declared, nil, true)
	stream := append(append([]byte{}, blk...), append([]byte("DATA"), trailing...)...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if _, err := v.next(); err != nil {
		t.Fatalf("next(): %v", err)
	}

	got, err := io.ReadAll(v.payload())
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != "DATA" {
		t.Fatalf("payload = %q, want %q", got, "DATA")
	}
}

// A RAR3 signature is not decodable. openVolume must say so rather than
// misparsing RAR3 blocks under the RAR5 layout.
func TestOpenVolumeRefusesRAR3(t *testing.T) {
	sig := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}
	_, err := openVolume(&mockReadCloser{bytes.NewReader(sig)})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("openVolume error = %v, want ErrUnsupportedFormat", err)
	}
}

// A volume truncated inside a block's payload must report exhaustion, not
// silently continue. The skip stops at EOF and the header read then fails.
func TestVolumeTruncatedInsidePayloadReportsEOF(t *testing.T) {
	blk := rar5BlockDeclaring(HeaderTypeFile, 100, nil, true)
	stream := append(append([]byte{}, blk...), []byte("short")...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if _, err := v.next(); err != nil {
		t.Fatalf("first next(): %v", err)
	}
	_, err = v.next()
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("second next() error = %v, want io.EOF or io.ErrUnexpectedEOF", err)
	}
}

// useEncryptedHeaders switches next() onto the decrypting header path, and
// the key it installs must not survive into a volume constructed afterward:
// header-encrypted multi-volume archives are meant to fail to parse rather
// than be misparsed under a stale key.
func TestVolumeUseEncryptedHeadersDecryptsAndDoesNotCarryAcrossVolumes(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	plain := rar5Block(func() []byte {
		var p bytes.Buffer
		p.Write(EncodeVint(HeaderTypeEnd))
		p.Write(EncodeVint(0))
		return p.Bytes()
	}())
	// CBC operates on whole 16-byte blocks; readEncryptedBlockHeader only
	// needs enough plaintext to cover the declared total, so zero-padding the
	// remainder of the final block is fine -- it is never inspected.
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)

	var stream bytes.Buffer
	stream.Write(iv)
	stream.Write(ciphertext)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(append([]byte{
		0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00,
	}, stream.Bytes()...))})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	v.useEncryptedHeaders(key)

	h, err := v.next()
	if err != nil {
		t.Fatalf("next(): %v", err)
	}
	if h.Type != HeaderTypeEnd {
		t.Fatalf("block type = %d, want HeaderTypeEnd", h.Type)
	}

	other, err := openVolume(&mockReadCloser{bytes.NewReader(append([]byte{
		0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00,
	}, rar5EndHeader()...))})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if other.hd != nil {
		t.Fatalf("new volume has a non-nil hd; the key must not carry across volumes")
	}
	if _, err := other.next(); err != nil {
		t.Fatalf("next() on the new plaintext volume: %v", err)
	}
}
