package rarengine

import (
	"errors"
	"fmt"
	"io"
)

type rar5Engine struct {
	sd       *StreamDecompressor
	dec50    *decoder50
	lzReader lz50Reader
	stReader storeReader
	mvReader multiVolumePayloadReader
	packed   packedCursor
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
	// Draining goes through the owner, so a file the caller skipped is
	// verified on the same terms as one it read.
	if err := re.sd.file.endFile(&re.packed); err != nil {
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

func (re *rar5Engine) processHeader(h *BlockHeader) (*FileHeader, bool, error) {
	switch h.Type {
	case HeaderTypeArchive:
		if _, err := ParseArchiveHeader(h); err != nil {
			return nil, false, err
		}

	case HeaderTypeFile:
		fh, err := ParseFileHeader(h)
		if err != nil {
			// Refusing a file must not leave its payload in the stream: the
			// next header would be parsed out of it, which for a crafted
			// archive means an entry fabricated from attacker-chosen bytes
			// surfacing from Next(). The block header is intact and
			// CRC-checked by this point whatever went wrong inside it -- only
			// the file-level fields are unusable -- so h.DataSize is
			// trustworthy and the payload can be dropped, leaving the
			// traversal able to reach the next file.
			//
			// This runs for every parse failure, not one named error. Which
			// field an archive corrupts is the archive's choice, so keying the
			// discard on a particular error left the same fabrication open
			// through every other one.
			return nil, false, re.sd.refuse(h.DataSize, err)
		}

		// A continuation block's bytes belong to the file its first block
		// already announced.
		if !fh.FirstBlock {
			return nil, true, re.sd.discardPayload(fh.PackedSize)
		}

		if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
			// Refused like any other rejected file, and for the same reason:
			// the caller can keep calling Next(), so leaving the payload lets
			// the block that was just refused supply the next "file".
			return nil, false, re.sd.refuse(fh.PackedSize, ErrRarBombDetected)
		}

		re.sd.win.Reset(fh.Solid)

		re.packed.repoint(re.sd.currentVol, fh.PackedSize)

		re.sd.file.begin(fh, re.newDecompressionReader(fh, re.packed.reader()), re.sd.verifyCRC)
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
		// Everything the caller never sees, including service records — quick
		// open, comment, recovery, ACL, stream. Those reuse the file-header
		// layout, so routing them to the file case above would surface one from
		// Next() as a file named after the record, e.g. "QO", and hand its bytes
		// over as file data. Their payload length is h.DataSize either way.
		if err := re.sd.discardPayload(h.DataSize); err != nil {
			return nil, false, err
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
	case HeaderTypeFile:
		fh, err := ParseFileHeader(h)
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
	case HeaderTypeEnd:
		if err := re.sd.nextVolume(); err != nil {
			return nil, false, err
		}
	default:
		// Everything the caller never sees, including service records — quick
		// open, comment, recovery, ACL, stream. Those reuse the file-header
		// layout, so routing them to the file case above would surface one from
		// Next() as a file named after the record, e.g. "QO", and hand its bytes
		// over as file data. Their payload length is h.DataSize either way.
		if err := re.sd.discardPayload(h.DataSize); err != nil {
			return nil, false, err
		}
	}
	return nil, true, nil
}

func (re *rar5Engine) nextVolumePayload() (io.Reader, error) {
	// The count describes the volume being left, and nextVolume closes that
	// volume before it can discover whether a next one exists. Dropping it
	// here keeps teardown from later draining a closed reader -- a read the
	// caller was told would not happen, on a handle it may have recycled.
	re.packed.invalidate()
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
			// The header in force says whether this is the file's final
			// block; anything else means the payload continues in the next
			// volume, so an inner EOF is a boundary rather than an end.
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

func (re *rar5Engine) newDecompressionReader(fh *FileHeader, pr io.Reader) io.Reader {
	// Derived up front, applied below the multi-volume splice. A non-nil key
	// is what says the file is encrypted from that point on.
	var decKey, decIV []byte
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
		decKey, decIV = key, fh.IV
	}

	// The multi-volume splice sits BELOW the decryption, not above it.
	//
	// A file's ciphertext is one continuous CBC stream that volume boundaries
	// cut at arbitrary offsets: the parts of an 8 KiB file measure 765, 764
	// and 599 bytes, none of them 16-byte aligned though they total a whole
	// number of blocks (8240 = 16 x 515). A later volume therefore begins mid-block and cannot
	// be decrypted on its own -- there is no per-volume IV to restart from,
	// and the header repeats the first part's salt and IV unchanged.
	//
	// Splicing above the decryption fed each new volume's raw bytes straight
	// to the decoder, so the first part decoded and every part after it was
	// ciphertext. Splicing below it lets one CBC reader carry its chaining
	// state across the boundary, and leaves the advance path with nothing to
	// know about encryption at all.
	re.mvReader.re = re
	re.mvReader.r = pr

	var src io.Reader = &re.mvReader
	if decKey != nil {
		decSrc, err := newCBCDecryptReader(src, decKey, decIV)
		if err != nil {
			return &errorReader{err: err}
		}
		src = decSrc
	}

	var r io.Reader
	if fh.Method == 0 {
		re.stReader.r = src
		re.stReader.win = re.sd.win
		r = &re.stReader
	} else {
		re.dec50.init(src, fh.FirstBlock)
		re.lzReader.dec = re.dec50
		re.lzReader.win = re.sd.win
		r = &re.lzReader
	}
	return r
}
