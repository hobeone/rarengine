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
)

// StreamDecompressor implements a sequential, tar-like reader for extracting RAR archives on-the-fly.
type StreamDecompressor struct {
	volumes        <-chan io.ReadCloser
	currentVol     io.ReadCloser
	currHeader     *FileHeader
	currReader     io.Reader
	win            *Window
	dec50          *decoder50
	password       string
	lzReader       lz50Reader
	stReader       storeReader
	mvReader       multiVolumePayloadReader
	limitPr        io.LimitedReader
	bytesRemaining int64
}

// SetPassword configures the decryption password for encrypted RAR archives.
func (sd *StreamDecompressor) SetPassword(password string) {
	sd.password = password
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
		volumes: volumes,
		win:     NewWindow(32 * 1024 * 1024), // 32MB sliding window history
		dec50:   newDecoder50(),
	}
}

// Reset reconfigures the decompressor for a new stream, reusing the sliding window and decoder.
func (sd *StreamDecompressor) Reset(volumes <-chan io.ReadCloser) {
	if sd.currentVol != nil {
		_ = sd.currentVol.Close()
		sd.currentVol = nil
	}
	sd.volumes = volumes
	sd.currHeader = nil
	sd.currReader = nil
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

	// Validate RAR5 magic signature: 0x52 0x61 0x72 0x21 0x1a 0x07 0x01 0x00
	var magic [8]byte
	_, err := io.ReadFull(sd.currentVol, magic[:])
	if err != nil {
		return err
	}
	expectedMagic := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}
	if !bytes.Equal(magic[:], expectedMagic) {
		return errors.New("rarengine: invalid RAR5 magic signature")
	}

	return nil
}

// Next advances to the next file in the RAR archive stream, returning its header.
// It returns io.EOF when all files in all volumes have been fully decompressed.
func (sd *StreamDecompressor) Next() (*FileHeader, error) {
	// 1. Drain the previous file payload if any remains unread to align the stream
	if sd.currReader != nil {
		if _, err := io.Copy(io.Discard, sd.currReader); err != nil {
			sd.currReader = nil
			return nil, fmt.Errorf("rarengine: draining previous file: %w", err)
		}
		sd.currReader = nil
	}

	// 2. Fetch the first volume if we haven't started yet
	if sd.currentVol == nil {
		if err := sd.nextVolume(); err != nil {
			return nil, err
		}
	}

	for {
		h, err := ReadBlockHeader(sd.currentVol)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Reached end of current volume stream, transition to next volume
				if err := sd.nextVolume(); err != nil {
					return nil, err // Returns ErrNoNextVolume (mapped to io.EOF by standard readers)
				}
				continue
			}
			return nil, err
		}

		switch h.Type {
		case HeaderTypeArchive:
			_, err := ParseArchiveHeader(h)
			if err != nil {
				return nil, err
			}

		case HeaderTypeFile, HeaderTypeService:
			fh, err := ParseFileHeader(h)
			if err != nil {
				return nil, err
			}

			if !fh.FirstBlock {
				// Skip the payload of the continuation block and find the next file
				_, err = io.Copy(io.Discard, io.LimitReader(sd.currentVol, fh.PackedSize))
				if err != nil {
					return nil, err
				}
				continue
			}

			// Compression Bomb (RAR-bomb) Protection: reject >1000x ratios for files > 1MB
			if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
				return nil, ErrRarBombDetected
			}

			sd.win.Reset(fh.Solid)

			sd.limitPr.R = sd.currentVol
			sd.limitPr.N = fh.PackedSize

			sd.currHeader = fh
			sd.bytesRemaining = fh.UnpackedSize
			sd.currReader = sd.newDecompressionReader(fh, &sd.limitPr)
			return fh, nil

		case HeaderTypeEnd:
			// Transition directly to the next volume
			if err := sd.nextVolume(); err != nil {
				return nil, err
			}
		default:
			if h.DataSize > 0 {
				_, err = io.Copy(io.Discard, io.LimitReader(sd.currentVol, h.DataSize))
				if err != nil {
					return nil, err
				}
			}
		}
	}
}

// Read reads decompressed bytes from the current active file block.
func (sd *StreamDecompressor) Read(p []byte) (int, error) {
	if sd.currReader == nil {
		return 0, ErrNoActiveFile
	}
	if sd.bytesRemaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > sd.bytesRemaining {
		p = p[:sd.bytesRemaining]
	}
	n, err := sd.currReader.Read(p)
	sd.bytesRemaining -= int64(n)
	if err == nil && sd.bytesRemaining <= 0 {
		return n, io.EOF
	}
	return n, err
}

// nextVolumePayload transitions to the next volume and searches for the continuation file header.
func (sd *StreamDecompressor) nextVolumePayload() (io.Reader, error) {
	if err := sd.nextVolume(); err != nil {
		return nil, err
	}
	for {
		h, err := ReadBlockHeader(sd.currentVol)
		if err != nil {
			return nil, err
		}
		switch h.Type {
		case HeaderTypeArchive:
			_, err := ParseArchiveHeader(h)
			if err != nil {
				return nil, err
			}
		case HeaderTypeFile, HeaderTypeService:
			fh, err := ParseFileHeader(h)
			if err != nil {
				return nil, err
			}
			sd.currHeader = fh
			return io.LimitReader(sd.currentVol, fh.PackedSize), nil
		case HeaderTypeEnd:
			if err := sd.nextVolume(); err != nil {
				return nil, err
			}
		default:
			if h.DataSize > 0 {
				_, err = io.Copy(io.Discard, io.LimitReader(sd.currentVol, h.DataSize))
				if err != nil {
					return nil, err
				}
			}
		}
	}
}

type multiVolumePayloadReader struct {
	sd *StreamDecompressor
	r  io.Reader
}

func (mv *multiVolumePayloadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := mv.r.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			if mv.sd.currHeader != nil && mv.sd.currHeader.LastBlock {
				return 0, io.EOF
			}
			nextR, nextErr := mv.sd.nextVolumePayload()
			if nextErr != nil {
				return 0, nextErr
			}
			mv.r = nextR
			continue
		}
		return 0, err
	}
}

// newDecompressionReader returns the window-integrated reader for the file payload.
func (sd *StreamDecompressor) newDecompressionReader(fh *FileHeader, pr io.Reader) io.Reader {
	if fh.Encrypted {
		if sd.password == "" {
			return &errorReader{err: errors.New("rarengine: password required for encrypted file")}
		}
		const maxKdfCount = 24 // RAR5 spec maximum
		if fh.KdfCount > maxKdfCount {
			return &errorReader{err: fmt.Errorf("rarengine: KdfCount %d exceeds maximum %d", fh.KdfCount, maxKdfCount)}
		}
		iter := 1 << fh.KdfCount
		passBytes := []byte(sd.password)
		key, pswCheckVal := pbkdf2HmacSha256(passBytes, fh.Salt, iter)
		if fh.EncCheck != nil {
			if err := verifyEncCheck(pswCheckVal, fh.EncCheck); err != nil {
				return &errorReader{err: err}
			}
		}
		decPr, err := newCBCDecryptReader(pr, key, fh.IV)
		if err != nil {
			return &errorReader{err: err}
		}
		pr = decPr
	}

	sd.mvReader.sd = sd
	sd.mvReader.r = pr

	var r io.Reader
	if fh.Method == 0 {
		sd.stReader.r = &sd.mvReader
		sd.stReader.win = sd.win
		r = &sd.stReader
	} else {
		sd.dec50.init(&sd.mvReader, fh.FirstBlock)
		sd.lzReader.dec = sd.dec50
		sd.lzReader.win = sd.win
		r = &sd.lzReader
	}
	return r
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
		return errors.New("rarengine: wrong password or corrupt encryption data")
	}
	return nil
}
