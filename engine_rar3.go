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
	if err := re.sd.finishCurrentFile(&re.packed); err != nil {
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

		fh, err := re.processHeader(h)
		if err != nil {
			return nil, err
		}
		if fh == nil {
			continue
		}
		return fh, nil
	}
}

// processHeader consumes one block and reports what it was.
//
// A nil header with a nil error means the block held nothing this caller wants
// -- an archive header, a continuation of a file already announced, a volume
// terminator, or a record type Next() does not surface -- and scanning
// continues. The two of those that carry file data have had it discarded by the
// time this returns: a continuation's packed bytes and an unrecognised block's
// h.DataSize. That discard is not tidiness. A block left in the stream is where
// the next header would be parsed from, which for a crafted archive means an
// entry fabricated out of attacker-chosen bytes.
//
// A non-nil header is the file to hand back, and by then it has been admitted:
// the window is reset, the packed cursor repointed, and fileReader begun. There
// is deliberately no third outcome. Returning a header while asking the caller
// to keep scanning would discard that header, since the caller returns it only
// when it stops.
func (re *rar3Engine) processHeader(h *BlockHeader) (*FileHeader, error) {
	switch h.Type {
	case 0x73: // Archive Header
		if h.Flags&mhdPassword > 0 {
			// Every block header after this one is ciphertext, so there is no
			// member to name and nothing to continue to -- this ends
			// traversal rather than producing a FileError.
			//
			// Left unchecked it ends traversal anyway, but only because the
			// encrypted bytes are unlikely to form a valid header. RAR3's
			// header checksum is a 16-bit truncation of CRC32, so each block
			// has roughly a 1-in-65536 chance of passing regardless, which
			// would surface a wholly fabricated file entry.
			return nil, ErrRAR3EncryptionUnsupported
		}
		return nil, nil

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
			return nil, re.sd.refuse(h.DataSize, err)
		}

		if !fh.FirstBlock {
			if err = re.sd.discardPayload(fh.PackedSize); err != nil {
				return nil, err
			}
			return nil, nil
		}

		if rar3ClaimsEncryption(fh) {
			// This library implements no RAR3 key derivation, so the content
			// cannot be produced whatever the caller supplies -- refused
			// rather than decrypted, and unconditionally rather than only
			// when no password was given.
			//
			// Refused here rather than deferred to a reader the way
			// engine_rar5.go handles its own encrypted files. The same
			// condition has to be caught again on every volume advance, where
			// the file is already begun and no reader is left to substitute,
			// so refusing at the header keeps one shape for both sites.
			//
			// Ahead of the rar-bomb check on purpose: both refuse through the
			// same path with the same payload discard, so a member that is
			// both merely reports the cause found first, and an encrypted
			// member is never decompressed either way.
			return nil, re.sd.refuseFile(fh, ErrRAR3EncryptionUnsupported)
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
			return nil, re.sd.refuseFile(fh, ErrRarBombDetected)
		}

		if err := re.sd.admitFile(fh); err != nil {
			return nil, err
		}

		re.sd.win.Reset(fh.Solid)

		re.packed.repoint(re.sd.currentVol, fh.PackedSize)

		re.sd.file.begin(fh, re.newDecompressionReader(fh, re.packed.reader()), re.sd.verifyCRC)
		return fh, nil

	case 0x7b: // Terminator block
		if err := re.sd.nextVolume(); err != nil {
			return nil, err
		}
		return nil, nil

	default:
		if h.DataSize > 0 {
			if err := re.sd.discardPayload(h.DataSize); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
}

// processVolumePayloadHeader consumes one block from a freshly opened volume
// and reports where the current file's bytes continue.
//
// A nil reader with a nil error means this block was not that continuation --
// the new volume's own archive header, a terminator, or an unrecognised block
// whose own data is discarded here -- and scanning continues into the next
// block. A
// non-nil reader is the payload source for the file already in progress, with
// the packed cursor repointed at this volume.
//
// The two outcomes are distinguished by the reader alone; there is no separate
// signal. A non-nil reader always means stop scanning, because the caller
// splices exactly what it is handed into the decode chain.
func (re *rar3Engine) processVolumePayloadHeader(h *BlockHeader) (io.Reader, error) {
	switch h.Type {
	case 0x73: // Archive Header
		if h.Flags&mhdPassword > 0 {
			// Checked again here for the same reason the file-header flag is:
			// a volume carries its own main header, and one that claims
			// header encryption when the opening volume did not is a claim
			// this engine would otherwise never look at. Ends traversal
			// rather than refusing a member -- the following headers are
			// ciphertext, so there is no member to name.
			return nil, ErrRAR3EncryptionUnsupported
		}
		return nil, nil
	case 0x74: // File Header
		fh, err := ParseRAR3FileHeader(h)
		if err != nil {
			return nil, re.sd.refuse(h.DataSize, err)
		}
		if rar3ClaimsEncryption(fh) {
			// The first-block guard cannot see this: a file's header is
			// parsed again on every volume advance, and this path builds no
			// reader -- it repoints the packed cursor and feeds the bytes
			// into the chain the first block already established. A member
			// whose first block was plain and whose continuation claims
			// encryption therefore had this volume's bytes delivered verbatim
			// as content, with a nil error and a header reporting
			// Encrypted false.
			//
			// refuse, not refuseFile. Not because refuseFile could not settle
			// its drain here -- it drives sd.discard itself and would settle
			// fine, which is exactly what makes the wrong choice easy to
			// make. The reason is that a file is still active at this point:
			// an error built here is laundered through endFile's verdict and
			// reaches the caller as the *FileError refuseFile constructed,
			// promising the stream is standing on the next block header. It
			// is not. nextVolumePayload abandoned re.packed on the advance,
			// so nothing backs that promise, and the caller would resume
			// traversal against an offset chosen by the archive.
			//
			// fh.PackedSize rather than h.DataSize, for the same reason the
			// rar-bomb site gives: the header parsed cleanly, so a large
			// file's high half is known.
			return nil, re.sd.refuse(fh.PackedSize, ErrRAR3EncryptionUnsupported)
		}

		re.sd.file.advanceVolume(fh)
		// Repointed rather than replaced by a fresh limiter: teardown drains
		// this cursor, and a limiter it cannot see would leave the count
		// describing a volume the stream has already moved past. Reusing it
		// also drops an allocation per volume.
		re.packed.repoint(re.sd.currentVol, fh.PackedSize)
		return re.packed.reader(), nil
	case 0x7b: // Terminator
		if err := re.sd.nextVolume(); err != nil {
			return nil, err
		}
	default:
		if h.DataSize > 0 {
			if err := re.sd.discardPayload(h.DataSize); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
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
		r, err := re.processVolumePayloadHeader(h)
		if err != nil {
			return nil, err
		}
		if r == nil {
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
