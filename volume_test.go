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

	// A second, independently-opened volume has hd == nil by construction --
	// there is no mechanism that could carry v's key into it, so asserting
	// that directly would pass against any implementation and prove nothing.
	// What can actually fail is this: if a key somehow did carry across, the
	// plaintext header below would be run through the decrypting path and
	// misread as ciphertext, and its CRC32 would not validate. Asserting that
	// next() succeeds AND returns the correct block type is a check the
	// no-carry-over guarantee can fail.
	other, err := openVolume(&mockReadCloser{bytes.NewReader(append([]byte{
		0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00,
	}, rar5EndHeader()...))})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	h, err = other.next()
	if err != nil {
		t.Fatalf("next() on the new plaintext volume: %v", err)
	}
	if h.Type != HeaderTypeEnd {
		t.Fatalf("new volume block type = %d, want HeaderTypeEnd", h.Type)
	}
}

// A header read that fails partway leaves v.rc at an offset next() cannot
// vouch for -- the size vint's continuation bytes are consumed before the
// truncation is discovered. A retry must not treat whatever bytes sit there
// next as a fresh block boundary: that is exactly how a crafted archive gets
// a fabricated entry back from a caller that retries after a transient-looking
// error.
//
// The archive shape: a valid RAR5 signature, then a 4-byte CRC followed by
// three size-vint bytes that all set the continuation bit (0x80) and never
// terminate, so DecodeVint fails having consumed exactly the 7 bytes
// ReadBlockHeader read up front. A complete, CRC-valid file block sits right
// after -- the bytes a broken retry would reparse as the next header.
func TestVolumeDoesNotResumeAfterFailedHeaderRead(t *testing.T) {
	planted := rar5BlockDeclaring(HeaderTypeFile, 5, nil, false)

	stream := append([]byte{}, rar5Signature...)
	stream = append(stream, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x80)
	stream = append(stream, planted...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}

	_, firstErr := v.next()
	if firstErr == nil {
		t.Fatalf("first next(): want an error (truncated vint), got nil")
	}

	h, err := v.next()
	if err == nil {
		t.Fatalf("second next() succeeded with header %+v; want the sticky "+
			"error from the first failed read, not a header fabricated from "+
			"the planted block's bytes", h)
	}
	if !errors.Is(err, firstErr) {
		t.Fatalf("second next() error = %v, want the same sticky error as "+
			"the first failed read (%v)", err, firstErr)
	}
}

// next() after Close() must not dereference the now-nil io.ReadCloser: a
// caller mistake must produce an error, not a crashed process.
func TestVolumeNextAfterCloseReturnsError(t *testing.T) {
	blk := rar5BlockDeclaring(HeaderTypeFile, 4, nil, true)
	stream := append(append([]byte{}, blk...), []byte("DATA")...)

	v, err := openVolume(&mockReadCloser{bytes.NewReader(stream)})
	if err != nil {
		t.Fatalf("openVolume: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := v.next(); err == nil {
		t.Fatalf("next() after Close(): want an error, got nil")
	}
}
