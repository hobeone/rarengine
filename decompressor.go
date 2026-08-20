package rarengine

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoNextVolume          = errors.New("rarengine: expected next volume stream from channel, but channel was closed")
	ErrUnexpectedVolumeBlock = errors.New("rarengine: unexpected block type in volume split transition")
	ErrNoActiveFile          = errors.New("rarengine: no active file stream to read from")
	ErrRarBombDetected       = errors.New("rarengine: possible RAR-bomb detected")

	// ErrCRCMismatch is returned by Read once a file's fully decompressed
	// content has been read, if its CRC32 doesn't match the value recorded
	// in the RAR file header. Only checked when the header carries a CRC32
	// (FileFlagHasCRC32) and VerifyCRC is enabled (the default). See
	// SetVerifyCRC.
	ErrCRCMismatch = errors.New("rarengine: decompressed content CRC32 does not match file header")

	// ErrWrongPassword is returned when an encrypted file's password check
	// value (PSWCHECK) doesn't match the supplied password. Wrap-checked
	// via errors.Is so callers can distinguish a bad password from other
	// decompression failures without parsing error text.
	ErrWrongPassword = errors.New("rarengine: wrong password or corrupt encryption data")

	// ErrPasswordRequired is returned when a file's header is encrypted but
	// no password was supplied. Callers that want to treat "no password
	// given" the same as "wrong password" (e.g. to prompt for one) can
	// check for either with errors.Is.
	ErrPasswordRequired = errors.New("rarengine: password required for encrypted file")
)

type ArchiveVersion int

const (
	VersionUnknown ArchiveVersion = iota
	VersionRAR3
	VersionRAR5
)

func (v ArchiveVersion) String() string {
	switch v {
	case VersionRAR3:
		return "RAR3"
	case VersionRAR5:
		return "RAR5"
	default:
		return "Unknown"
	}
}

// versionedEngine is the per-format half of decoding: walking block headers
// and installing each file. Reading a file's bytes is deliberately not part
// of it -- both engines had byte-identical Read and checksum implementations,
// and fileReader now owns that for both.
type versionedEngine interface {
	Next() (*FileHeader, error)
}

// StreamDecompressor implements a sequential, tar-like reader for extracting RAR archives on-the-fly.
type StreamDecompressor struct {
	volumes    <-chan io.ReadCloser
	currentVol io.ReadCloser
	// file owns all per-file decode state: the reader chain, the header in
	// force, the byte budget, the running checksum and the terminal error.
	file      fileReader
	version   ArchiveVersion
	engine    versionedEngine
	win       *Window
	password  string
	verifyCRC bool
	// discard backs discardPayload. Reused so discarding a block's payload
	// costs no allocation, per the no-new-allocations rule in CLAUDE.md.
	discard packedCursor
	// damaged records that a file was skipped without delivering everything
	// it declared, so the LZ77 window is missing bytes a solid successor
	// would back-reference. Set by finishCurrentFile, consulted and cleared
	// by admitFile -- those two are the only places allowed to touch it.
	damaged bool
}

// finishCurrentFile ends the active file and remembers whether it left the
// window incomplete.
//
// The engines call this rather than sd.file.endFile directly so that the
// damage state has exactly one writer. Reading it back out of the returned
// error at each call site would put the same rule in two engines and let them
// drift, which is how the refusal paths diverged before.
func (sd *StreamDecompressor) finishCurrentFile(packed *packedCursor) error {
	short, err := sd.file.endFile(packed)
	// Keyed on short, NOT on whether a FileError came back. The two answer
	// different questions: FileError asks "may the caller resume?", short asks
	// "is the window intact?". Deriving one from the other left every
	// non-continuable short file -- a truncated volume, a failed drain --
	// recorded as undamaged, so a solid file on the next volume decoded
	// against history its predecessor never wrote.
	if short {
		sd.damaged = true
	}
	return err
}

// admitFile decides whether a file may begin, given what happened to the
// files before it.
//
// A non-solid file resets the window, so it and everything built on it are
// unaffected by earlier damage -- that is what clears the state. A solid file
// after damage cannot be decoded correctly and is refused: see
// ErrSolidStreamBroken.
func (sd *StreamDecompressor) admitFile(fh *FileHeader) error {
	if !fh.Solid {
		sd.damaged = false
		return nil
	}
	if sd.damaged {
		// Refused here rather than at each engine's call site. The refusal and
		// the admission decision are one rule, and this codebase's two engines
		// have repeatedly diverged where a rule was written down twice --
		// which is the same reason the damage state has a single writer.
		return sd.refuse(fh.PackedSize, ErrSolidStreamBroken)
	}
	return nil
}

// packedCursor tracks how many packed bytes a block still owes the stream, and
// which volume owes them.
//
// It exists because "how much payload is left" is read and written from
// several places -- the engine on each volume advance, the decode chain as it
// consumes bytes, and the teardown that discards whatever is unread -- and an
// unguarded io.LimitedReader shared between them is what let a count captured
// on one volume be applied to another. Mutation goes through repoint and
// invalidate; consumption goes through reader and drain. Nothing else may
// touch the count.
//
// Reused rather than reallocated per volume: a fresh limiter on each advance
// is both an allocation and a value the previous holder cannot see.
type packedCursor struct {
	lr io.LimitedReader
	// abandoned records that the count reached zero by being dropped rather
	// than by being read.
	//
	// Both outcomes leave owed() == 0, and they mean opposite things about
	// where the stream is: a drained cursor leaves it on the next block
	// header, an abandoned one leaves it wherever the volume advance gave up.
	// Anything deciding whether the traversal can safely resume has to tell
	// them apart, so the distinction lives here rather than being inferred
	// from a count that cannot carry it.
	abandoned bool
}

// repoint aims the cursor at n bytes of r, replacing whatever it described
// before. Called when a file begins and again on every volume advance, so the
// count always belongs to the volume actually being read.
func (c *packedCursor) repoint(r io.Reader, n int64) {
	c.lr.R, c.lr.N = r, n
	c.abandoned = false
}

// invalidate forgets the outstanding count without reading anything.
//
// Required before the stream leaves a volume: nextVolume closes the current
// volume before it can discover whether a next one exists, so a count left
// standing would later be drained out of a closed reader -- a read the caller
// was told would not happen, on a handle it may already have recycled.
func (c *packedCursor) invalidate() {
	c.lr.N = 0
	c.abandoned = true
}

// reader exposes the cursor as the payload source for a decode chain.
func (c *packedCursor) reader() io.Reader {
	return &c.lr
}

// owed reports how many packed bytes remain unread.
func (c *packedCursor) owed() int64 {
	return c.lr.N
}

// settled reports that every byte this cursor promised was actually read, and
// so that the stream is standing on the next block header.
//
// It is deliberately not owed() == 0. invalidate zeroes the count without
// reading, and the volume-advance path invalidates before it discovers whether
// a next volume exists -- so a failure there (a header that fails its CRC, a
// refused header, a channel that closed) leaves the count at zero with the
// stream parked wherever the failed read stopped. Treating that as drained is
// what let a crafted archive choose the offset a later header was parsed from.
func (c *packedCursor) settled() bool {
	return c.lr.N == 0 && !c.abandoned
}

// drain discards whatever the cursor still owes, so the next block header is
// read from the stream's real structure rather than from the tail of a file's
// payload.
//
// A short drain is not an error. When a volume is truncated the promised bytes
// are simply absent from the media, so io.Copy stops at the underlying EOF
// with the count still standing; the stream is then at the end of that volume,
// where the next read advances rather than parsing anything out of payload.
func (c *packedCursor) drain() error {
	if c.lr.N <= 0 {
		return nil
	}
	_, err := io.Copy(io.Discard, &c.lr)
	if err != nil {
		// Named, because endFile may report this alongside the file's own
		// verdict and the two are otherwise indistinguishable in the joined
		// message: one says the file is bad, this one says the stream is no
		// longer positioned at a block boundary.
		return fmt.Errorf("rarengine: draining packed remainder: %w", err)
	}
	return nil
}

// discardPayload consumes n bytes of block payload from the current volume, for
// blocks whose contents the caller never sees: continuation blocks already
// accounted for, service records, unrecognized block types, and files refused
// after their header was read.
func (sd *StreamDecompressor) discardPayload(n int64) error {
	if n <= 0 {
		return nil
	}
	sd.discard.repoint(sd.currentVol, n)
	return sd.discard.drain()
}

// refuse drops n bytes of a rejected file's payload and returns cause, the
// reason the file was rejected.
//
// Every refusal has to do both, because traversal continues afterwards: the
// caller gets the error and calls Next() again, so a refused block that keeps
// its payload supplies the next entry. Pairing them here rather than at each
// refusal site keeps the two from drifting apart, and a failed discard wins
// over cause -- if the stream cannot be repositioned, nothing later can be
// trusted regardless of why this file was refused.
func (sd *StreamDecompressor) refuse(n int64, cause error) error {
	if err := sd.discardPayload(n); err != nil {
		return err
	}
	return cause
}

// SetPassword configures the decryption password for encrypted RAR archives.
func (sd *StreamDecompressor) SetPassword(password string) {
	sd.password = password
}

// SetVerifyCRC controls whether Read returns ErrCRCMismatch when a file's
// decompressed content doesn't match the CRC32 recorded in its RAR header.
// Enabled by default: a RAR archive's per-file CRC32 is the only signal
// this library has that the bytes it decoded are actually correct — without
// it, a structurally well-formed but content-corrupt archive (e.g. assembled
// from an incomplete download) decodes "successfully" while silently
// producing wrong data. Callers that want best-effort extraction regardless
// of content correctness (e.g. salvaging whatever is recoverable from a
// damaged archive) can disable verification explicitly.
func (sd *StreamDecompressor) SetVerifyCRC(verify bool) {
	sd.verifyCRC = verify
}

// Version returns the detected archive version (RAR3 or RAR5) of the active stream.
func (sd *StreamDecompressor) Version() ArchiveVersion {
	return sd.version
}

type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, e.err
}

// NewStreamDecompressor initializes the decompressor with a channel of incoming volume streams.
func NewStreamDecompressor(volumes <-chan io.ReadCloser) *StreamDecompressor {
	return &StreamDecompressor{
		volumes:   volumes,
		win:       NewWindow(32 * 1024 * 1024), // 32MB sliding window history
		verifyCRC: true,
	}
}

// Reset reconfigures the decompressor for a new stream, reusing the sliding window.
func (sd *StreamDecompressor) Reset(volumes <-chan io.ReadCloser) {
	if sd.currentVol != nil {
		_ = sd.currentVol.Close()
		sd.currentVol = nil
	}
	sd.volumes = volumes
	// Clearing the file drops any terminal error with it; without this a
	// reused decompressor would inherit the previous stream's failure.
	sd.file.clear()
	// Same reason as clearing the file: damage belongs to the stream that
	// caused it, and a reused decompressor would otherwise refuse the next
	// archive's solid files over a failure they had nothing to do with.
	sd.damaged = false
	sd.version = VersionUnknown
	sd.engine = nil
	sd.win.Reset(false)
}

// nextVolume fetches the next volume from the channel, closing the previous one if active.
func (sd *StreamDecompressor) nextVolume() error {
	if sd.currentVol != nil {
		_ = sd.currentVol.Close()
	}

	vol, ok := <-sd.volumes
	if !ok {
		return ErrNoNextVolume
	}
	sd.currentVol = vol

	version, err := detectVersion(sd.currentVol)
	if err != nil {
		return err
	}

	sd.version = version
	if sd.engine == nil {
		switch version {
		case VersionRAR5:
			sd.engine = newRAR5Engine(sd)
		case VersionRAR3:
			sd.engine = newRAR3Engine(sd)
		}
	}

	return nil
}

func detectVersion(r io.Reader) (ArchiveVersion, error) {
	var magic [7]byte
	_, err := io.ReadFull(r, magic[:])
	if err != nil {
		return VersionUnknown, err
	}
	expectedMagicStart := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07}
	if !bytes.Equal(magic[:6], expectedMagicStart) {
		return VersionUnknown, errors.New("rarengine: invalid RAR magic signature")
	}

	if magic[6] == 0x00 {
		return VersionRAR3, nil
	}
	if magic[6] == 0x01 {
		var lastByte [1]byte
		_, err = io.ReadFull(r, lastByte[:])
		if err != nil {
			return VersionUnknown, err
		}
		if lastByte[0] == 0x00 {
			return VersionRAR5, nil
		}
	}
	return VersionUnknown, errors.New("rarengine: invalid RAR magic signature")
}

// Next advances to the next file in the RAR archive stream, returning its header.
func (sd *StreamDecompressor) Next() (*FileHeader, error) {
	if sd.currentVol == nil {
		if err := sd.nextVolume(); err != nil {
			return nil, err
		}
	}
	return sd.engine.Next()
}

// Read reads decompressed bytes from the current active file.
//
// Once a file fails -- a checksum mismatch, a truncated stream, or a decode
// error -- that error is returned by every subsequent Read for that file
// rather than decaying to io.EOF. Advance with Next to move on.
//
// Note that io.ReadFull cannot see an error delivered alongside the final
// bytes, because io.ReadAtLeast discards it once enough bytes have arrived.
// A caller reading exactly UnpackedSize that way must Read once more, or use
// io.Copy, to observe the file's verdict.
func (sd *StreamDecompressor) Read(p []byte) (int, error) {
	return sd.file.Read(p)
}

type lz50Reader struct {
	dec *decoder50
	win *Window
}

func (l *lz50Reader) Read(p []byte) (int, error) {
	return l.dec.Read(l.win, p)
}

type storeReader struct {
	r   io.Reader
	win *Window
}

func (s *storeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.win.writeBytes(p[:n])
	}
	return n, err
}

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
			// fileReader.finish exists to prevent one layer up, which is not a
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
