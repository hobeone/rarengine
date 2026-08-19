package rarengine

import (
	"errors"
	"io"
)

type rar3Engine struct {
	sd       *StreamDecompressor
	stReader storeReader
	rar3Dec  *rar3Decoder
	mvReader multiVolumePayloadReader3
	limitPr  io.LimitedReader
}

func newRAR3Engine(sd *StreamDecompressor) *rar3Engine {
	return &rar3Engine{
		sd:      sd,
		rar3Dec: newRAR3Decoder(sd.win),
	}
}

func (re *rar3Engine) Next() (*FileHeader, error) {
	// Draining goes through the owner, so a file the caller skipped is
	// verified on the same terms as one it read.
	if err := re.sd.file.endFile(); err != nil {
		return nil, err
	}

	for {
		h, err := ReadRAR3BlockHeader(re.sd.currentVol)
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

func (re *rar3Engine) processHeader(h *BlockHeader) (*FileHeader, bool, error) {
	switch h.Type {
	case 0x73: // Archive Header
		return nil, true, nil

	case 0x74: // File Header
		fh, err := ParseRAR3FileHeader(h)
		if err != nil {
			return nil, false, err
		}

		if !fh.FirstBlock {
			if err = re.sd.discardPayload(fh.PackedSize); err != nil {
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

		re.sd.file.begin(fh, re.newDecompressionReader(fh, &re.limitPr), re.sd.verifyCRC)
		return fh, false, nil

	case 0x7b: // Terminator block
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
		return nil, true, nil

	default:
		if h.DataSize > 0 {
			if err := re.sd.discardPayload(h.DataSize); err != nil {
				return nil, false, err
			}
		}
		return nil, true, nil
	}
}

func (re *rar3Engine) processVolumePayloadHeader(h *BlockHeader) (io.Reader, bool, error) {
	switch h.Type {
	case 0x73: // Archive Header
		return nil, true, nil
	case 0x74: // File Header
		fh, err := ParseRAR3FileHeader(h)
		if err != nil {
			return nil, false, err
		}
		re.sd.file.advanceVolume(fh)
		return io.LimitReader(re.sd.currentVol, fh.PackedSize), false, nil
	case 0x7b: // Terminator
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
	default:
		if h.DataSize > 0 {
			if err := re.sd.discardPayload(h.DataSize); err != nil {
				return nil, false, err
			}
		}
	}
	return nil, true, nil
}

func (re *rar3Engine) nextVolumePayload() (io.Reader, error) {
	if err := re.sd.nextVolume(); err != nil {
		return nil, err
	}
	for {
		h, err := ReadRAR3BlockHeader(re.sd.currentVol)
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

type multiVolumePayloadReader3 struct {
	re *rar3Engine
	r  io.Reader
}

func (mv *multiVolumePayloadReader3) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := mv.r.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			if mv.re.sd.file.lastBlock() {
				return 0, io.EOF
			}
			nextR, nextErr := mv.re.nextVolumePayload()
			if nextErr != nil {
				return 0, nextErr
			}
			mv.r = nextR
			continue
		}
		return 0, err
	}
}

func (re *rar3Engine) newDecompressionReader(fh *FileHeader, pr io.Reader) io.Reader {
	re.mvReader.re = re
	re.mvReader.r = pr

	var r io.Reader
	if fh.Method == 0 {
		re.stReader.r = &re.mvReader
		re.stReader.win = re.sd.win
		r = &re.stReader
	} else {
		re.rar3Dec.Reset(&re.mvReader, fh.UnpackedSize, fh.Solid)
		r = re.rar3Dec
	}
	return r
}
