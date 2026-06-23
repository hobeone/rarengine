package rarengine

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

type rar5Engine struct {
	sd             *StreamDecompressor
	dec50          *decoder50
	lzReader       lz50Reader
	stReader       storeReader
	mvReader       multiVolumePayloadReader
	limitPr        io.LimitedReader
	bytesRemaining int64
	crc            uint32
	// headerDec decrypts subsequent header blocks once a HEAD_CRYPT header
	// (archive-level header encryption) has been seen. nil means headers
	// are plaintext. Not reset across volumes -- multi-volume archives with
	// header encryption are not currently supported.
	headerDec *headerDecrypter
}

func newRAR5Engine(sd *StreamDecompressor) *rar5Engine {
	return &rar5Engine{
		sd:    sd,
		dec50: newDecoder50(),
	}
}

func (re *rar5Engine) Next() (*FileHeader, error) {
	if err := re.drainPrevious(); err != nil {
		return nil, err
	}

	for {
		h, err := re.readBlockHeader()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				if err := re.sd.nextVolume(); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}

		fh, shouldContinue, err := re.processHeader(h)
		if err != nil {
			return nil, err
		}
		if shouldContinue {
			continue
		}
		return fh, nil
	}
}

// readBlockHeader reads the next header block, transparently decrypting it
// if the archive's headers are encrypted (a HEAD_CRYPT header was already
// seen and parsed by processHeader).
func (re *rar5Engine) readBlockHeader() (*BlockHeader, error) {
	if re.headerDec != nil {
		return re.headerDec.readEncryptedBlockHeader(re.sd.currentVol)
	}
	return ReadBlockHeader(re.sd.currentVol)
}

func (re *rar5Engine) Read(p []byte) (int, error) {
	if re.sd.currReader == nil {
		return 0, ErrNoActiveFile
	}
	if re.bytesRemaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > re.bytesRemaining {
		p = p[:re.bytesRemaining]
	}
	n, err := re.sd.currReader.Read(p)
	re.crc = crc32.Update(re.crc, crc32.IEEETable, p[:n])
	re.bytesRemaining -= int64(n)
	if err == nil && re.bytesRemaining <= 0 {
		if crcErr := re.checkCRC(); crcErr != nil {
			return n, crcErr
		}
		return n, io.EOF
	}
	return n, err
}

// checkCRC compares the running CRC32 of this file's decompressed content
// against the value recorded in its RAR header, once all bytes have been
// read. A no-op when verification is disabled or the header carries no
// CRC32 (FileFlagHasCRC32 unset).
func (re *rar5Engine) checkCRC() error {
	if !re.sd.verifyCRC {
		return nil
	}
	fh := re.sd.currHeader
	if fh == nil || !fh.HasCRC32 {
		return nil
	}
	if re.crc != fh.CRC32 {
		return fmt.Errorf("%w: file %q: computed=%08x header=%08x", ErrCRCMismatch, fh.Name, re.crc, fh.CRC32)
	}
	return nil
}

func (re *rar5Engine) drainPrevious() error {
	if re.sd.currReader != nil {
		if _, err := io.Copy(io.Discard, re.sd.currReader); err != nil {
			re.sd.currReader = nil
			return fmt.Errorf("rarengine: draining previous file: %w", err)
		}
		re.sd.currReader = nil
	}
	return nil
}

func (re *rar5Engine) processHeader(h *BlockHeader) (*FileHeader, bool, error) {
	switch h.Type {
	case HeaderTypeArchive:
		if _, err := ParseArchiveHeader(h); err != nil {
			return nil, false, err
		}

	case HeaderTypeFile, HeaderTypeService:
		fh, err := ParseFileHeader(h)
		if err != nil {
			return nil, false, err
		}

		if !fh.FirstBlock {
			if _, err = io.Copy(io.Discard, io.LimitReader(re.sd.currentVol, fh.PackedSize)); err != nil {
				return nil, false, err
			}
			return nil, true, nil
		}

		if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
			return nil, false, ErrRarBombDetected
		}

		re.sd.win.Reset(fh.Solid)

		re.limitPr.R = re.sd.currentVol
		re.limitPr.N = fh.PackedSize

		re.sd.currHeader = fh
		re.bytesRemaining = fh.UnpackedSize
		re.crc = 0
		re.sd.currReader = re.newDecompressionReader(fh, &re.limitPr)
		return fh, false, nil

	case HeaderTypeEncryption:
		ch, err := ParseCryptHeader(h)
		if err != nil {
			return nil, false, err
		}
		key, err := headerKeyFromPassword(ch, re.sd.password)
		if err != nil {
			return nil, false, err
		}
		re.headerDec = &headerDecrypter{key: key}

	case HeaderTypeEnd:
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
	default:
		if h.DataSize > 0 {
			if _, err := io.Copy(io.Discard, io.LimitReader(re.sd.currentVol, h.DataSize)); err != nil {
				return nil, false, err
			}
		}
	}
	return nil, true, nil
}

func (re *rar5Engine) processVolumePayloadHeader(h *BlockHeader) (io.Reader, bool, error) {
	switch h.Type {
	case HeaderTypeArchive:
		if _, err := ParseArchiveHeader(h); err != nil {
			return nil, false, err
		}
	case HeaderTypeFile, HeaderTypeService:
		fh, err := ParseFileHeader(h)
		if err != nil {
			return nil, false, err
		}
		re.sd.currHeader = fh
		return io.LimitReader(re.sd.currentVol, fh.PackedSize), false, nil
	case HeaderTypeEnd:
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
	default:
		if h.DataSize > 0 {
			if _, err := io.Copy(io.Discard, io.LimitReader(re.sd.currentVol, h.DataSize)); err != nil {
				return nil, false, err
			}
		}
	}
	return nil, true, nil
}

func (re *rar5Engine) nextVolumePayload() (io.Reader, error) {
	if err := re.sd.nextVolume(); err != nil {
		return nil, err
	}
	for {
		h, err := ReadBlockHeader(re.sd.currentVol)
		if err != nil {
			return nil, err
		}
		r, shouldContinue, err := re.processVolumePayloadHeader(h)
		if err != nil {
			return nil, err
		}
		if shouldContinue {
			continue
		}
		return r, nil
	}
}

type multiVolumePayloadReader struct {
	re *rar5Engine
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
			var currHeader *FileHeader
			if mv.re != nil {
				currHeader = mv.re.sd.currHeader
			} else if mv.sd != nil {
				currHeader = mv.sd.currHeader
			}
			if currHeader != nil && currHeader.LastBlock {
				return 0, io.EOF
			}
			var nextR io.Reader
			var nextErr error
			if mv.re != nil {
				nextR, nextErr = mv.re.nextVolumePayload()
			} else if mv.sd != nil {
				if mv.sd.engine == nil {
					mv.sd.engine = newRAR5Engine(mv.sd)
				}
				nextR, nextErr = mv.sd.engine.(*rar5Engine).nextVolumePayload()
			}
			if nextErr != nil {
				return 0, nextErr
			}
			mv.r = nextR
			continue
		}
		return 0, err
	}
}

func (re *rar5Engine) newDecompressionReader(fh *FileHeader, pr io.Reader) io.Reader {
	if fh.Encrypted {
		if re.sd.password == "" {
			return &errorReader{err: ErrPasswordRequired}
		}
		const maxKdfCount = 24
		if fh.KdfCount > maxKdfCount {
			return &errorReader{err: fmt.Errorf("rarengine: KdfCount %d exceeds maximum %d", fh.KdfCount, maxKdfCount)}
		}
		iter := 1 << fh.KdfCount
		passBytes := []byte(re.sd.password)
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

	re.mvReader.re = re
	re.mvReader.r = pr

	var r io.Reader
	if fh.Method == 0 {
		re.stReader.r = &re.mvReader
		re.stReader.win = re.sd.win
		r = &re.stReader
	} else {
		re.dec50.init(&re.mvReader, fh.FirstBlock)
		re.lzReader.dec = re.dec50
		re.lzReader.win = re.sd.win
		r = &re.lzReader
	}
	return r
}
