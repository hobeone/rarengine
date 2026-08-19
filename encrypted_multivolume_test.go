package rarengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// encryptedMultiVolumeChan feeds every part of one of the encrypted
// multi-volume fixtures, in order.
func encryptedMultiVolumeChan(t *testing.T, prefix string) <-chan io.ReadCloser {
	t.Helper()

	names, err := filepath.Glob(filepath.Join("testdata", prefix+".part*.rar"))
	if err != nil {
		t.Fatalf("globbing %s parts: %v", prefix, err)
	}
	if len(names) < 2 {
		t.Fatalf("found %d parts of %s; the fixture must span volumes to "+
			"exercise anything here", len(names), prefix)
	}
	// Glob sorts lexically and the parts are zero-padded to two digits, so
	// this is volume order.
	volumes := make(chan io.ReadCloser, len(names))
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		volumes <- &mockReadCloser{bytes.NewReader(b)}
	}
	close(volumes)
	return volumes
}

// TestEncryptedMultiVolume_DecodesEveryVolume is the reproduction for a file
// that is both encrypted and split across volumes.
//
// A file's ciphertext is one continuous CBC stream, and volume boundaries cut
// it at arbitrary offsets: this fixture's parts are 757, 756 and 631 bytes,
// none of them a whole number of AES blocks though together they are. A later
// volume therefore starts mid-block and cannot be decrypted on its own -- the
// headers repeat the first part's salt and IV rather than supplying new ones,
// so there is nothing to restart from.
//
// Splicing volumes above the decryption fed each new part's raw bytes to the
// decoder, so the first part decoded and every part after it was ciphertext.
// The two methods failed differently and both are pinned: the compressed
// decoder reads ahead into the next volume before emitting anything and died
// on garbage with zero output, while the store reader emitted the first part
// intact and then garbage.
func TestEncryptedMultiVolume_DecodesEveryVolume(t *testing.T) {
	decoded := map[string][]byte{}

	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{"compressed", "rar5_encrypted_multi"},
		{"store", "rar5_encrypted_multi_store"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := NewStreamDecompressor(encryptedMultiVolumeChan(t, tc.prefix))
			sd.SetPassword("test")

			fh, err := sd.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			if !fh.Encrypted {
				t.Fatal("fixture is not encrypted, so it cannot exercise this path")
			}

			got, err := io.ReadAll(sd)
			// An encrypted file's recorded digest is not a plaintext CRC32, so
			// completion is reported as unverifiable rather than as a match.
			// That is another test's subject; here it must simply not be a
			// decode failure.
			if err != nil && !errors.Is(err, ErrChecksumUnsupported) {
				t.Fatalf("reading: %v", err)
			}
			if int64(len(got)) != fh.UnpackedSize {
				t.Fatalf("read %d of %d declared bytes", len(got), fh.UnpackedSize)
			}
			decoded[tc.name] = got
		})
	}

	// Both fixtures were built from the same source, one compressed and one
	// stored, so they must decode identically. This is the anchor: it needs no
	// external tool and no committed copy of the plaintext, and the two
	// failure modes are different enough (the compressed decoder produced
	// nothing at all, the store reader produced the first volume then
	// garbage) that a common bug cannot make them agree by accident.
	if len(decoded) != 2 {
		t.Fatal("one of the fixtures did not decode; nothing to compare")
	}
	if !bytes.Equal(decoded["compressed"], decoded["store"]) {
		t.Errorf("the two encodings of the same file decoded differently, "+
			"first at offset %d (%d vs %d bytes)",
			firstDifference(decoded["compressed"], decoded["store"]),
			len(decoded["compressed"]), len(decoded["store"]))
	}
}

// TestEncryptedMultiVolume_ChecksumIsReportedUnverifiable pins what a caller
// sees on success. An encrypted file records a transformed digest rather than
// a CRC32 of its plaintext -- measured on these fixtures, one records 9ef0f342
// where the content's CRC32 is 4a7f9844 -- so comparing it as a CRC32 accuses
// correct data of being corrupt.
//
// ErrChecksumUnsupported says the digest cannot be checked, which is true, and
// leaves the caller free to accept the content. ErrCRCMismatch would say the
// content is wrong, which is false.
func TestEncryptedMultiVolume_ChecksumIsReportedUnverifiable(t *testing.T) {
	sd := NewStreamDecompressor(encryptedMultiVolumeChan(t, "rar5_encrypted_multi"))
	sd.SetPassword("test")

	if _, err := sd.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	_, err := io.ReadAll(sd)
	if !errors.Is(err, ErrChecksumUnsupported) {
		t.Fatalf("reading an encrypted file returned %v; want "+
			"ErrChecksumUnsupported. ErrCRCMismatch here would report correct "+
			"content as corrupt", err)
	}
}

// TestCBCDecryptReader_KeepsSubBlockRemainder is the unit-level pin for the
// defect the fixtures above surface.
//
// CBC consumes whole 16-byte blocks, but an io.Reader may return any count it
// likes. Bytes past the last whole block have to be held until the next call
// completes the block; discarding them silently drops data. This is not
// specific to multi-volume archives -- any reader that returns a short or
// unaligned count triggers it -- so it is pinned here against a reader that
// simply hands back awkward sizes.
func TestCBCDecryptReader_KeepsSubBlockRemainder(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// A whole number of blocks, as RAR stores, and long enough that the read
	// sizes below are not silently clamped to the data's length -- a clamp
	// would round the first chunk back to a block boundary and the test would
	// pass without ever producing a remainder.
	plain := make([]byte, 16*80)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)

	// 757 is the size of the fixture's first volume payload and is what made
	// the discarded remainder visible: 47 whole blocks and 5 bytes over.
	sizes := []int{757, 13, 1, 300}
	// Asserted, not assumed: the whole point is a read that ends mid-block, so
	// a size list that happens to be block-aligned would test nothing.
	for _, s := range sizes {
		if s%16 == 0 {
			t.Fatalf("read size %d is block-aligned; these must not be, or no "+
				"remainder is ever produced", s)
		}
	}
	if sizes[0] >= len(ciphertext) {
		t.Fatalf("first read (%d) covers the whole ciphertext (%d), so it "+
			"would be clamped to a block boundary and produce no remainder",
			sizes[0], len(ciphertext))
	}

	r, err := newCBCDecryptReader(
		&chunkedReader{data: ciphertext, sizes: sizes}, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("decrypted %d bytes of %d, first difference at %d; a read that "+
			"ended mid-block dropped its remainder instead of carrying it",
			len(got), len(plain), firstDifference(got, plain))
	}
}

// chunkedReader returns the sizes it is given, in order, then whatever is
// left. It models a source whose read sizes have nothing to do with the
// cipher's block size -- a volume boundary, a socket, a pipe.
type chunkedReader struct {
	data  []byte
	sizes []int
	off   int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := len(p)
	if len(c.sizes) > 0 {
		n = c.sizes[0]
		c.sizes = c.sizes[1:]
	}
	if n > len(p) {
		n = len(p)
	}
	if c.off+n > len(c.data) {
		n = len(c.data) - c.off
	}
	copy(p, c.data[c.off:c.off+n])
	c.off += n
	return n, nil
}

// firstDifference reports the index of the first differing byte, or the length
// of the shorter slice when one is a prefix of the other. -1 means equal.
func firstDifference(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}
