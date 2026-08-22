package rarengine

// Package-internal cryptographic primitives for RAR5 encryption.
//
// AES key material -- the password, the derived key bytes, and the salt --
// must never appear in an error message or log line produced from this file.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

type cbcDecryptReader struct {
	r         io.Reader
	decrypter cipher.BlockMode
	inBuf     [4096]byte
	// inLen is how much of inBuf is held but not yet decrypted: the tail of a
	// read that ended mid-block. CBC consumes whole 16-byte blocks, and a
	// Reader may return any count it likes, so those bytes have to survive
	// until the next call completes the block. Dropping them silently
	// corrupted every encrypted multi-volume file, whose parts are sliced at
	// arbitrary offsets -- 765 bytes in the first volume decrypts 47 blocks
	// and strands 13.
	inLen    int
	outBlock [4096]byte
	outBuf   []byte
	err      error
}

func newCBCDecryptReader(r io.Reader, key []byte, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(block, iv)
	return &cbcDecryptReader{
		r:         r,
		decrypter: decrypter,
	}, nil
}

func (c *cbcDecryptReader) Read(p []byte) (int, error) {
	if len(c.outBuf) > 0 {
		n := copy(p, c.outBuf)
		c.outBuf = c.outBuf[n:]
		return n, nil
	}
	// Held-back bytes are still owed to the caller, so a recorded EOF only
	// ends the stream once they have been consumed.
	if c.err != nil && c.inLen == 0 {
		return 0, c.err
	}

	// Fill until a whole block is available, resuming from whatever the last
	// call held back rather than starting at zero.
	for c.inLen < 16 && c.err == nil {
		n, err := c.r.Read(c.inBuf[c.inLen:])
		c.inLen += n
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.err = io.EOF
				break
			}
			// Recorded, not just returned. Left unrecorded, a caller that
			// reads again re-enters this loop, and a source that then reports
			// EOF sends the held bytes down the partial-block path below --
			// reporting ErrUnexpectedEOF and losing the real failure. The
			// held bytes go with it: after a hard error the stream is broken,
			// and keeping a fragment only to mislabel it later helps nobody.
			c.err = err
			c.inLen = 0
			return 0, err
		}
	}
	if c.inLen < 16 {
		if c.inLen > 0 {
			// RAR pads a file's ciphertext to whole blocks, so a partial block
			// at the end of the stream means it was cut short rather than
			// that the format allows one.
			//
			// Recorded so it survives a second call. Returning it while
			// leaving c.err at io.EOF let the next Read report a clean end of
			// stream, decaying a truncation into success -- the exact decay
			// Entry.finish exists to prevent one layer up, which is not a
			// reason for this layer to produce it.
			c.inLen = 0
			c.err = io.ErrUnexpectedEOF
		}
		return 0, c.err
	}

	decryptLen := (c.inLen / 16) * 16
	c.decrypter.CryptBlocks(c.outBlock[:decryptLen], c.inBuf[:decryptLen])
	// Carry the sub-block tail into the next call.
	rem := c.inLen - decryptLen
	copy(c.inBuf[:rem], c.inBuf[decryptLen:c.inLen])
	c.inLen = rem
	c.outBuf = c.outBlock[:decryptLen]

	n := copy(p, c.outBuf)
	c.outBuf = c.outBuf[n:]
	return n, nil
}

// pbkdf2HmacSha256 runs RAR5's key derivation, which reads three values off
// one continuous PBKDF2 chain rather than three separate derivations: the
// first iter iterations produce the AES key, the next 16 produce
// HashKeyValue, and 16 after that produce PswCheckValue.
//
// The two 16-iteration loops below are therefore identical by coincidence of
// count, not duplication -- the boundary between them is where HashKeyValue
// falls. This function discards it, because HashKeyValue is only needed for
// the key-derived MAC that UseMac selects, which this library refuses with
// ErrChecksumUnsupported rather than checking. Collapsing the two into a
// single 32-iteration loop computes the same bytes and erases the only place
// that value could be taken from.
func pbkdf2HmacSha256(password, salt []byte, iter int) ([]byte, []byte) {
	mac := hmac.New(sha256.New, password)
	var block [4]byte
	binary.BigEndian.PutUint32(block[:], 1)
	mac.Reset()
	mac.Write(salt)
	mac.Write(block[:])
	u := mac.Sum(nil)

	fn := append([]byte(nil), u...)

	for j := 1; j < iter; j++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for k := range fn {
			fn[k] ^= u[k]
		}
	}
	key := append([]byte(nil), fn...)

	for range 16 {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for k := range fn {
			fn[k] ^= u[k]
		}
	}

	for range 16 {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for k := range fn {
			fn[k] ^= u[k]
		}
	}
	pswCheckVal := append([]byte(nil), fn...)

	return key, pswCheckVal
}

func verifyEncCheck(pswCheckVal, encCheck []byte) error {
	if len(encCheck) < 8 {
		return errors.New("rarengine: corrupt encryption check data")
	}
	var expected [8]byte
	for i := range 32 {
		expected[i%8] ^= pswCheckVal[i]
	}
	if !bytes.Equal(encCheck[:8], expected[:]) {
		return ErrWrongPassword
	}
	return nil
}
