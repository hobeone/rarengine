package rarengine

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

type versionedEngine interface {
	Next() (*FileHeader, error)
	Read(p []byte) (int, error)
}

// StreamDecompressor implements a sequential, tar-like reader for extracting RAR archives on-the-fly.
type StreamDecompressor struct {
	volumes    <-chan io.ReadCloser
	currentVol io.ReadCloser
	currHeader *FileHeader
	currReader io.Reader
	version    ArchiveVersion
	engine     versionedEngine
	win        *Window
	password   string
	verifyCRC  bool
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
	sd.currHeader = nil
	sd.currReader = nil
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

// Read reads decompressed bytes from the current active file block.
func (sd *StreamDecompressor) Read(p []byte) (int, error) {
	if sd.engine == nil {
		return 0, ErrNoActiveFile
	}
	return sd.engine.Read(p)
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
	outBlock  [4096]byte
	outBuf    []byte
	err       error
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
	if c.err != nil {
		return 0, c.err
	}

	var totalRead int
	for totalRead < 16 {
		n, err := c.r.Read(c.inBuf[totalRead:])
		if n > 0 {
			totalRead += n
		}
		if err != nil {
			if err == io.EOF {
				c.err = io.EOF
				break
			}
			return 0, err
		}
	}
	if totalRead < 16 {
		if totalRead > 0 {
			return 0, io.ErrUnexpectedEOF
		}
		return 0, io.EOF
	}

	decryptLen := (totalRead / 16) * 16
	c.decrypter.CryptBlocks(c.outBlock[:decryptLen], c.inBuf[:decryptLen])
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
