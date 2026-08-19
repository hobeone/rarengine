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
	packed   packedCursor
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
	if err := re.sd.file.endFile(&re.packed); err != nil {
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
			// Refusing a file must not leave its payload in the stream, or the
			// next header is parsed out of attacker-chosen bytes.
			//
			// h.DataSize is the only size available here: it comes from the
			// block framing, which is intact, while fh -- and with it the
			// high half of a large file's packed size -- is exactly what
			// failed to parse. A corrupt LHD_LARGE header can therefore still
			// leave its high bytes behind, which no amount of care here can
			// recover, because nothing in the stream says how many there are.
			return nil, false, re.sd.refuse(h.DataSize, err)
		}

		if !fh.FirstBlock {
			if err = re.sd.discardPayload(fh.PackedSize); err != nil {
				return nil, false, err
			}
			return nil, true, nil
		}

		if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
			// Refused like any other rejected file, and for the same reason:
			// the caller can keep calling Next(), so leaving the payload lets
			// the block that was just refused supply the next "file".
			//
			// fh.PackedSize rather than h.DataSize: RAR3 splits a large file's
			// packed size across ADD_SIZE and HIGH_PACK_SIZE, and h.DataSize
			// carries only the low half. The header parsed cleanly here, so
			// the full size is known and is what has to go.
			return nil, false, re.sd.refuse(fh.PackedSize, ErrRarBombDetected)
		}

		re.sd.win.Reset(fh.Solid)

		re.packed.repoint(re.sd.currentVol, fh.PackedSize)

		re.sd.file.begin(fh, re.newDecompressionReader(fh, re.packed.reader()), re.sd.verifyCRC)
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
			return nil, false, re.sd.refuse(h.DataSize, err)
		}
		re.sd.file.advanceVolume(fh)
		// Repointed rather than replaced by a fresh limiter: teardown drains
		// this cursor, and a limiter it cannot see would leave the count
		// describing a volume the stream has already moved past. Reusing it
		// also drops an allocation per volume.
		re.packed.repoint(re.sd.currentVol, fh.PackedSize)
		return re.packed.reader(), false, nil
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
	// The count describes the volume being left, and nextVolume closes that
	// volume before it can discover whether a next one exists. Dropping it
	// here keeps teardown from later draining a closed reader.
	re.packed.invalidate()
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
