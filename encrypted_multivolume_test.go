package rarengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
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
	//
	// engine_rar5_service_test.go has a fixtureVolumes helper that does this
	// from bare names, but it is in package rarengine_test and this file has
	// to be in package rarengine to reach newCBCDecryptReader.
	volumes := make(chan io.ReadCloser, len(names))
	for _, name := range names {
		volumes <- &mockReadCloser{bytes.NewReader(fixtureBytes(t, filepath.Base(name)))}
	}
	close(volumes)
	return volumes
}

// TestEncryptedMultiVolume_DecodesEveryVolume is the reproduction for a file
// that is both encrypted and split across volumes.
//
// A file's ciphertext is one continuous CBC stream, and volume boundaries cut
// it at arbitrary offsets: the compressed fixture's parts are 765, 764 and 599
// bytes (8240 = 16 x 515) and the stored one's are 765, 764 and 551
// (8192 = 16 x 512). No part is a whole number of AES blocks though each file
// is. A later volume therefore starts mid-block and cannot be decrypted on its
// own -- the headers repeat the first part's salt and IV rather than supplying
// new ones, so there is nothing to restart from.
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
			// These fixtures record a key-derived MAC on their last part, so
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
// sees on success, and guards the split-header bug specifically.
//
// RAR records this file's digest as a key-derived MAC and sets UseMac on the
// header carrying it -- the LAST part's. Part 1 has the flag clear, and the
// CRC32 field it does carry covers that part's packed bytes rather than the
// file's plaintext ("unrar lt" labels it "Pack-CRC32" there and "CRC32 MAC" on
// part 11). Reading UseMac when the file began therefore saw the cleared copy
// and went on to compare a plaintext CRC32 against a MAC, a guaranteed
// mismatch on every encrypted multi-volume file.
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

	// 765 is the size of the fixture's first volume payload and is what made
	// the discarded remainder visible: 47 whole blocks and 13 bytes over.
	sizes := []int{765, 13, 1, 300}
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
	n := min(len(b), len(a))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// TestRAR3_EncryptedFlagCannotSuppressCRCCheck pins that the RAR3 header's
// LHD_PASSWORD bit cannot turn checksum verification off.
//
// The RAR3 engine does not decrypt: newDecompressionReader never consults the
// password and never splices a CBC reader, so a file carrying this flag is
// delivered as-is. Gating verification on FileHeader.Encrypted -- which is set
// straight from that bit -- therefore handed a crafted archive an off switch,
// reachable with no password and without the caller ever calling SetPassword:
// flip the bit, append 8 salt bytes, fix the 16-bit header CRC, and a payload
// that fails its CRC32 reports as ErrChecksumUnsupported ("cannot check this")
// instead of ErrCRCMismatch ("this content is wrong"). A caller whose policy is
// "accept unverifiable, reject mismatch" -- the policy ErrChecksumUnsupported
// exists to enable -- would accept the tampered bytes.
//
// UseMac is the only sanctioned exemption, and RAR3 never sets it.
//
// The encrypted half of that argument is now closed at an earlier point: a
// member carrying either encryption bit is refused before it decodes, so the
// bit cannot reach verification at all. What this test still pins is the
// plain case -- that an ordinary member's mismatch is reported as
// ErrCRCMismatch -- plus the negative half of the encrypted case: whatever a
// crafted archive does with these bits, the outcome is never a clean read and
// never ErrChecksumUnsupported. See TestRAR3_EncryptedMemberIsRefused for the
// positive assertion about what the refusal is.
// TestRAR3_EncryptedMemberIsRefused pins that a RAR3 member this library
// cannot decrypt is refused at Next(), rather than having its ciphertext
// decoded as though it were content.
//
// Both bits are covered, and they are not the same bit. LHD_PASSWORD (0x0004)
// is what says the member is encrypted; LHD_SALT (0x0400) says eight salt
// bytes follow the name. Real RAR 3.x encryption sets both, so an honest
// archive trips a guard keyed on either one -- and a crafted archive sets only
// LHD_PASSWORD, which is exactly the case a salt-keyed guard would miss.
//
// The declared CRC matches the payload on purpose. Without the guard the
// stored cases decode to a clean success with a nil error, so these subtests
// fail against unfixed code by admitting the member rather than by reporting
// some other error.
// TestRAR3_EncryptedRefusalContinuesTraversal pins the other half of what the
// *FileError promises: the stream is standing on the next block header, so the
// members behind a refused one are still reachable.
// TestRAR3_EncryptedContinuationIsRefused covers the route the first-block
// guard cannot see.
//
// A file header is parsed again on every volume advance, and that path builds
// no new reader -- it repoints the packed cursor at the new volume and feeds
// the bytes into the decode chain the first block already established. So a
// member whose first block is plain and whose continuation carries an
// encryption bit had its second volume's bytes delivered verbatim as content,
// with a nil error and a header reporting Encrypted=false. That is a quieter
// failure than the one this file's other tests cover, because nothing in the
// caller's loop reports anything at all.
//
// Refused with the bare sentinel rather than a *FileError: the packed cursor
// is invalidated before the volume advance, so settled() is false by
// construction and no honest continuation promise can be made here.
// TestRAR3_EncryptedArchiveHeaderIsRefused covers whole-archive header
// encryption (MHD_PASSWORD), where every block header after the main one is
// ciphertext.
//
// Refused at the archive level rather than per member, because there is no
// member to name: the headers that would name one cannot be read. Left
// unchecked, such an archive fails only because the encrypted bytes do not
// happen to form a valid header -- and RAR3's header checksum is a 16-bit
// truncation, so each block carries a roughly 1-in-65536 chance of passing
// anyway and surfacing a fabricated entry.
// TestRAR3_EncryptedArchiveHeaderOnLaterVolumeIsRefused covers the archive
// flag at the other site: a volume carries its own main header, so a set of
// volumes can claim header encryption from the second one onwards.
// TestRAR3_EncryptedRefusalOnTruncatedPayloadIsNotContinuable pins the
// settled() gate at the new call site.
//
// refuseFile only promises continuation when the payload was drained by being
// read. Here the archive ends mid-payload, so the drain cannot complete and
// the caller must get the bare sentinel -- never a *FileError, which would
// claim the stream is standing on a block header it is not standing on.
// errAfterBytes hands out data, fails once with a non-EOF error, and reports
// io.EOF from then on.
//
// Failing only once is the whole point. A source that repeats its error makes
// any consumer look durable, because the durability comes from the source
// rather than from the code under test -- an earlier version of this helper did
// exactly that and the subtest passed against the unfixed reader. Reporting EOF
// afterwards also models the realistic case: a volume that has already failed
// has nothing further to give.
type errAfterBytes struct {
	data      []byte
	off       int
	failAt    int
	err       error
	together  bool
	delivered bool
}

func (e *errAfterBytes) Read(p []byte) (int, error) {
	if e.delivered {
		return 0, io.EOF
	}
	remaining := e.failAt - e.off
	if remaining <= 0 {
		e.delivered = true
		return 0, e.err
	}
	n := min(min(len(p), remaining), len(e.data)-e.off)
	copy(p, e.data[e.off:e.off+n])
	e.off += n
	if e.together && e.off >= e.failAt {
		e.delivered = true
		return n, e.err
	}
	return n, nil
}

// TestCBCDecryptReader_TerminalErrorsAreDurable pins that a failure reported by
// this reader stays reported.
//
// CLAUDE.md requires a file's terminal error to be durable, and fileReader
// enforces that one layer up. That is not a licence for this layer to hand out
// a failure and then a clean io.EOF: the decoders between the two call Read
// more than once, so an error that decays here can reach fileReader as success
// and never become terminal at all.
func TestCBCDecryptReader_TerminalErrorsAreDurable(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 16*4)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)

	readErr := errors.New("source exploded")

	for _, tc := range []struct {
		name string
		src  func() io.Reader
		want error
	}{
		{
			// Ciphertext cut mid-block. RAR pads to whole blocks, so this is
			// truncation, and it must not become io.EOF on a second call.
			name: "truncated mid-block",
			src:  func() io.Reader { return bytes.NewReader(ciphertext[:len(ciphertext)-5]) },
			want: io.ErrUnexpectedEOF,
		},
		{
			// A hard error after a sub-block fragment is buffered. Without the
			// error being recorded, the retry path turns it into
			// ErrUnexpectedEOF and the real cause is gone.
			name: "hard error, reported separately",
			src: func() io.Reader {
				return &errAfterBytes{data: ciphertext, failAt: 20, err: readErr}
			},
			want: readErr,
		},
		{
			// Same, but bytes and error arrive from one call, which io.Reader
			// explicitly allows.
			name: "hard error, reported with bytes",
			src: func() io.Reader {
				return &errAfterBytes{data: ciphertext, failAt: 20, err: readErr, together: true}
			},
			want: readErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newCBCDecryptReader(tc.src(), key, iv)
			if err != nil {
				t.Fatal(err)
			}

			// Drain whatever the reader is willing to produce, then find the
			// error it settles on.
			var first error
			for range 100 {
				buf := make([]byte, 64)
				_, first = r.Read(buf)
				if first != nil {
					break
				}
			}
			if !errors.Is(first, tc.want) {
				t.Fatalf("first terminal error = %v, want %v", first, tc.want)
			}

			// The point of the test: read again.
			for i := range 3 {
				buf := make([]byte, 64)
				n, again := r.Read(buf)
				if n != 0 {
					t.Fatalf("call %d produced %d bytes after a terminal error", i+2, n)
				}
				if !errors.Is(again, tc.want) {
					t.Fatalf("call %d returned %v, want %v; a terminal error "+
						"decayed into a different verdict", i+2, again, tc.want)
				}
			}
		})
	}
}
