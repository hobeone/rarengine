package rarengine

import (
	"errors"
	"fmt"
	"io"
)

type rar3Engine struct {
	sd             *StreamDecompressor
	stReader       storeReader
	mvReader       multiVolumePayloadReader3
	limitPr        io.LimitedReader
	bytesRemaining int64
}

func newRAR3Engine(sd *StreamDecompressor) *rar3Engine {
	return &rar3Engine{
		sd: sd,
	}
}

func (re *rar3Engine) Next() (*FileHeader, error) {
	if err := re.drainPrevious(); err != nil {
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

func (re *rar3Engine) Read(p []byte) (int, error) {
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
	re.bytesRemaining -= int64(n)
	if err == nil && re.bytesRemaining <= 0 {
		return n, io.EOF
	}
	return n, err
}

func (re *rar3Engine) drainPrevious() error {
	if re.sd.currReader != nil {
		if _, err := io.Copy(io.Discard, re.sd.currReader); err != nil {
			re.sd.currReader = nil
			return fmt.Errorf("rarengine: draining previous file: %w", err)
		}
		re.sd.currReader = nil
	}
	return nil
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
		re.sd.currReader = re.newDecompressionReader(fh, &re.limitPr)
		return fh, false, nil

	case 0x7b: // Terminator block
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
		return nil, true, nil

	default:
		if h.DataSize > 0 {
			if _, err := io.Copy(io.Discard, io.LimitReader(re.sd.currentVol, h.DataSize)); err != nil {
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
		re.sd.currHeader = fh
		return io.LimitReader(re.sd.currentVol, fh.PackedSize), false, nil
	case 0x7b: // Terminator
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
			if mv.re.sd.currHeader != nil && mv.re.sd.currHeader.LastBlock {
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
		r = &errorReader{err: fmt.Errorf("rarengine: compression method %d not implemented", fh.Method)}
	}
	return r
}
