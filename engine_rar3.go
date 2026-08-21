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
	// fatal ends traversal permanently once the stream can no longer be
	// resynchronised. Every other refusal in this engine discards the offending
	// block first, so the stream is left standing on the next header and the
	// caller may keep going; the one case that cannot is a block whose length
	// is itself unreadable. Continuing from there would read the next header
	// out of that block's payload, which is the fabrication this whole file
	// guards against.
	//
	// Not cleared here: Reset drops the engine entirely, so a reused
	// decompressor builds a fresh one.
	fatal error
}

func newRAR3Engine(sd *StreamDecompressor) *rar3Engine {
	return &rar3Engine{
		sd:      sd,
		rar3Dec: newRAR3Decoder(sd.win),
	}
}

func (re *rar3Engine) Next() (*FileHeader, error) {
	// Checked before anything reads: once the stream cannot be resynchronised,
	// every later header would come out of a block this engine could not skip.
	if re.fatal != nil {
		return nil, re.fatal
	}

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
// continues. A non-nil header is the file to hand back, and by then it has been
// admitted: the window is reset, the packed cursor repointed, and fileReader
// begun.
//
// Every block's declared payload is accounted for before either happens,
// because a block left in the stream is where the next header gets parsed from
// -- which for a crafted archive means an entry fabricated out of
// attacker-chosen bytes. DataSize is read from a header flag with no
// restriction on block type, so any block may declare one, not only a file.
//
// The accounting is by default rather than by obligation: a case that does
// nothing falls out of the switch to dropDeclaredPayload, and only a case that
// has handled the payload itself returns early. Read the returns as the
// exceptions they are -- each carries a comment saying which of the three
// reasons it is (the file claims it; a refusal already discarded it; the volume
// advanced and took it away). Errors decided inside the switch are recorded in
// cause rather than returned, so that refusing a block still drops its payload.
//
// The value and the continue-decision are one signal, in both directions.
// Returning a header while asking the caller to keep scanning would discard
// that header, since the caller returns it only when it stops -- and returning
// nil to mean "stop with nothing" is equally unavailable, because the caller
// reads that as "keep scanning" and reads another header from a stream that may
// have ended. A path that needs either shape must reintroduce an explicit
// signal rather than reaching for a nil.
func (re *rar3Engine) processHeader(h *BlockHeader) (*FileHeader, error) {
	// Recorded rather than returned, so that a refusal decided inside the
	// switch still reaches the discard below. Returning from a case is what
	// says "this block's payload is already accounted for"; a refusal decided
	// here has accounted for nothing.
	var cause error

	switch h.Type {
	case rar3BlockMain:
		if h.Flags&mhdPassword > 0 {
			// Every block header after this one is ciphertext, so there is no
			// member to name and nothing to continue to -- this ends
			// traversal rather than producing a FileError.
			//
			// Terminal, not merely reported. This block's own payload is
			// discarded on the way out, so the stream is positioned correctly
			// -- but every header after it is ciphertext, and RAR3's header
			// checksum is a 16-bit truncation of CRC32, so scanning it gives
			// roughly a 1-in-65536 chance per block of accepting a wholly
			// fabricated entry. Relying on ciphertext to be unparseable is
			// relying on the archive not to have searched for bytes that parse.
			re.fatal = ErrRAR3EncryptionUnsupported
			cause = ErrRAR3EncryptionUnsupported
		}

	case rar3BlockFile:
		fh, err := ParseRAR3FileHeader(h)
		if err != nil {
			// A file whose header failed to parse while claiming lhdLarge
			// cannot be skipped at all: h.DataSize is only the low 32 bits, and
			// the high half lives in the structure that just proved unreadable.
			// Discarding the low half alone lands mid-payload, so the next
			// header would come out of the remainder. Terminal for the same
			// reason dropDeclaredPayload's is.
			if h.Flags&lhdLarge > 0 {
				re.fatal = ErrRAR3UnmeasurablePayload
				return nil, re.fatal
			}
			// Otherwise h.DataSize is the whole payload and refusing is safe:
			// it comes from the block framing, which is intact and CRC-checked,
			// while only the file-level fields are unusable.
			return nil, re.sd.refuse(h.DataSize, err)
		}

		// Returns because this path discards the payload itself -- that is the
		// discriminator, not the size it uses. The size is why it cannot
		// instead fall through: fh.PackedSize composes the high half that
		// lhdLarge puts in the header, and h.DataSize is only the low 32 bits,
		// so the shared discard would leave the rest in the stream.
		if !fh.FirstBlock {
			return nil, re.sd.discardPayload(fh.PackedSize)
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

		// Returns rather than falling through, and the reason is invisible at
		// this line: admitFile's refusal path calls refuse, which discards
		// fh.PackedSize itself. It reads like plain error propagation, so a rule
		// phrased over syntax -- "error returns become cause" -- would send it
		// to the discard below and consume a second payload out of the next
		// block. The rule is "has this path already discarded", which is
		// answered by following the call, not by reading the line.
		if err := re.sd.admitFile(fh); err != nil {
			return nil, err
		}

		re.sd.win.Reset(fh.Solid)

		re.packed.repoint(re.sd.currentVol, fh.PackedSize)

		// Returns because the file claims the payload. Falling through here
		// would discard the exact bytes the cursor was just repointed at,
		// truncating the file mid-volume with its count still standing --
		// the most severe way this switch can be got wrong.
		re.sd.file.begin(fh, re.newDecompressionReader(fh, re.packed.reader()), re.sd.verifyCRC)
		return fh, nil

	case rar3BlockTerminator:
		// Returns because the stream has moved on: nextVolume closed this
		// volume, so its remaining bytes are unreachable and h.DataSize no
		// longer describes anything readable. That holds only because every
		// failure in nextVolume clears sd.currentVol -- see its doc comment.
		if err := re.sd.nextVolume(); err != nil {
			return nil, err
		}
		return nil, nil

	default:
		// Falls through to the discard, which is the whole point of the
		// default: an unrecognised block is exactly the case nobody thought
		// about, and it needs no thought to be handled correctly.
	}

	return nil, re.settle(h, cause)
}

// settle is the shared exit of both dispatchers: it accounts for whatever
// payload the block declared, then reports the refusal the switch recorded.
//
// One helper rather than the same tail written at each exit, for the reason the
// inversion exists at all -- a rule copied to every site is a rule each site can
// be edited out of. A change to this contract, such as joining the two errors
// rather than letting the discard failure win, is then one edit.
func (re *rar3Engine) settle(h *BlockHeader, cause error) error {
	if err := re.dropDeclaredPayload(h); err != nil {
		// The drain failure wins over cause, matching refuse: if the stream
		// cannot be repositioned then nothing after this point is trustworthy,
		// and reporting why the block was refused would imply it is.
		return err
	}
	return cause
}

// dropDeclaredPayload discards the bytes a block declared and no case claimed.
//
// This is the single point every unclaimed path in both dispatchers reaches, so
// that accounting for a block's payload is what happens by default and keeping
// it is what takes a deliberate return. The inversion is deliberate: the
// previous shape made the discard a per-case obligation, and three separate
// changes to these switches forgot it, each time letting a crafted archive have
// the next header parsed out of the leftover bytes.
//
// The failure mode is inverted along with the control flow. A forgotten discard
// used to leak payload -- silent, and the leaked bytes are attacker-chosen. A
// forgotten return now over-consumes instead, eating the following block, which
// surfaces as a header CRC failure. Loud and wrong beats silent and wrong.
func (re *rar3Engine) dropDeclaredPayload(h *BlockHeader) error {
	if rar3UsesFileLayout(h.Type) && h.Flags&lhdLarge > 0 {
		// Scoped to the subblock types on purpose. lhdLarge is 0x0100, which on
		// a main header is mhdFirstVolume and entirely legitimate, so testing
		// the bit alone would refuse ordinary archives.
		//
		// Deliberately NOT also gated on h.DataSize > 0. h.DataSize is only the
		// low 32 bits of the packed size, so a block whose true size is an exact
		// multiple of 4 GiB -- or one simply built with ADD_SIZE zero and a
		// non-zero high half -- reads as declaring nothing. Requiring it here
		// let exactly those blocks past the guard and into discardPayload(0),
		// which consumes nothing and leaves the whole payload in the stream.
		// The flag is the claim that matters; the declared size is not evidence
		// against it.
		//
		// Terminal, unlike every other refusal here. The others discard the
		// block and leave the stream on the next header, so traversal resumes
		// safely; this one cannot, because the number of bytes to skip is
		// precisely what could not be read.
		re.fatal = ErrRAR3UnmeasurablePayload
		return ErrRAR3UnmeasurablePayload
	}
	return re.sd.discardPayload(h.DataSize)
}

// processVolumePayloadHeader consumes one block from a freshly opened volume
// and reports where the current file's bytes continue.
//
// A nil reader with a nil error means this block was not that continuation --
// the new volume's own archive header, a terminator, or an unrecognised block
// whose own data is discarded here -- and scanning continues into the next
// block. A non-nil reader is the payload source for the file already in
// progress, with the packed cursor repointed at this volume.
//
// Accounting for a declared payload matters more here than at the Next() site:
// a header parsed out of an undiscarded region reaches repoint below, aiming
// the packed cursor at attacker-chosen bytes that are then spliced into the
// file in progress as its content. The same default-discard shape as
// processHeader applies -- see its doc comment for the rule and the three
// reasons a case may return instead.
//
// Those two are distinguished by the reader alone; there is no separate signal,
// and a non-nil reader always means stop scanning, because the caller splices
// exactly what it is handed into the decode chain.
//
// The error return is the third outcome and is not interchangeable with them. A
// continuation claiming encryption is refused here through refuse rather than
// refuseFile, because a file is still active at this point and refuseFile would
// promise the stream is standing on the next block header when nextVolumePayload
// has just abandoned the packed cursor. See the call site below, and CLAUDE.md.
func (re *rar3Engine) processVolumePayloadHeader(h *BlockHeader) (io.Reader, error) {
	// Same contract as processHeader's: recorded rather than returned so a
	// refusal decided in the switch still reaches the discard.
	var cause error

	switch h.Type {
	case rar3BlockMain:
		if h.Flags&mhdPassword > 0 {
			// Checked again here for the same reason the file-header flag is:
			// a volume carries its own main header, and one that claims
			// header encryption when the opening volume did not is a claim
			// this engine would otherwise never look at. Ends traversal
			// rather than refusing a member -- the following headers are
			// ciphertext, so there is no member to name.
			//
			// Latched for the same reason as the processHeader site: a retry
			// would scan ciphertext through a 16-bit checksum.
			re.fatal = ErrRAR3EncryptionUnsupported
			cause = ErrRAR3EncryptionUnsupported
		}
	case rar3BlockFile:
		fh, err := ParseRAR3FileHeader(h)
		if err != nil {
			// Terminal when lhdLarge is claimed, for the reason the same site
			// in processHeader gives: the high half of the packed size is
			// inside the header that failed, so the block cannot be skipped.
			if h.Flags&lhdLarge > 0 {
				re.fatal = ErrRAR3UnmeasurablePayload
				return nil, re.fatal
			}
			// Returns: refuse discarded h.DataSize itself.
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
		// Returns because the file claims the payload -- and here the cursor
		// has just been repointed at exactly these bytes, so falling through
		// would hand the file a truncated volume with its count still owed.
		return re.packed.reader(), nil
	case rar3BlockTerminator:
		if err := re.sd.nextVolume(); err != nil {
			return nil, err
		}
		// This return is load-bearing and was added with the inversion. The
		// case previously ended here and fell out to a shared `return nil, nil`,
		// which was correct when falling out did nothing. Falling out now
		// discards, and the volume this block declared its payload on has
		// already been closed.
		return nil, nil
	default:
	}

	return nil, re.settle(h, cause)
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
		if re.fatal != nil {
			return nil, re.fatal
		}
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
