package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
)

// volume owns one RAR volume's byte stream and the position within it.
//
// It is the only way the traversal obtains a block header, and next()
// re-establishes the block boundary itself before reading one. A header
// therefore cannot be parsed out of a previous block's payload -- not because
// every caller remembers to discard, but because no caller is offered the
// chance to skip.
//
// The skip is at the front of the only entrance deliberately. A finish()-style
// call after the fact would be exactly as forgettable as the per-case discard
// this type replaces; putting it before the read discharges the obligation as
// a side effect of asking for the thing the caller wanted anyway.
//
// The count lives here rather than beside the traversal because a volume
// advance CONSTRUCTS A NEW volume rather than repointing this one. A count
// outliving the volume it describes is therefore not a rule to follow but a
// lifetime that cannot occur, which is what makes the previous cursor's
// invalidate/abandoned/settled distinction unnecessary.
type volume struct {
	rc io.ReadCloser

	// body is what remains of the current block's declared payload. It is the
	// bound on payload() as well as the amount next() skips, and those are the
	// same number by construction: a RAR5 file header's PackedSize is set from
	// the block's DataSize (header.go), so no second count can disagree.
	body io.LimitedReader

	// hd decrypts subsequent block headers once an encryption header has
	// yielded a key. nil means headers are plaintext.
	hd *headerDecrypter

	// err is sticky once set: any failure inside next() -- the payload skip or
	// the header read itself, plaintext or encrypted -- leaves v.rc at an
	// offset next() cannot vouch for. A header read that fails partway through
	// (a truncated size vint, an IV read that succeeds but the ciphertext that
	// follows doesn't) has already consumed some number of bytes from v.rc,
	// and neither the caller nor this type knows how many. That unknown
	// position is exactly what lets a crafted archive choose where the next
	// header gets parsed from: retrying the read treats whatever bytes sit
	// there next as a fresh block boundary, when they are actually the
	// interior of whatever failed to parse. Recording err here and returning
	// it on every subsequent call, without touching v.rc again, is what keeps
	// a failed read from being retried into a fabricated header.
	err error

	// closeOnce makes Close idempotent without mutating rc. The previous
	// idempotency test was `v.rc == nil`, which required Close to nil rc -- a
	// write racing every traversal read of that field, from the one method
	// another goroutine may call. Once, plus an immutable rc, removes the
	// write instead of synchronising it, and absorbs the concurrent double
	// Close that leaving r.vol non-nil makes possible -- Reader.Close and the
	// traversal can now both reach the same volume.
	//
	// sync.Once and not an atomic CAS: Once establishes happens-before for
	// every caller, so a second caller's read of closeErr is ordered after the
	// first's write. A CAS would make the flag safe and leave closeErr racy.
	// (Reader.done is closed under volMu rather than by a Once for the
	// opposite reason -- Reset replaces it. A volume is never reset.)
	//
	// These two fields cost 32 bytes per volume, measured: one volume per
	// advance, never per byte, with the allocation count unchanged.
	closeOnce sync.Once
	closeErr  error

	// signed records that readSignature has consumed the RAR signature from
	// rc, so next() may read a block header. nextVolume publishes a volume
	// BEFORE reading its signature -- that is what lets Reader.Close reach a
	// stream stalled in that read -- which means r.vol briefly points at a
	// volume positioned at byte 0.
	//
	// Nothing can observe that today: the traversal goroutine is r.vol's only
	// reader and it is the goroutine blocked inside the read, and Close
	// touches nothing but Close(). This flag is what makes the guarantee
	// structural rather than conventional, because the convention is one
	// concurrency change away from false -- volume prefetch would let a
	// reader reach r.vol mid-read, and next() would then skip nothing (body.N
	// is 0) and parse a block header straight out of the signature bytes.
	//
	// Written by readSignature only, read by next() only, both on the
	// traversal goroutine. Not concurrency state: it is never read under
	// volMu and Reader.Close never touches it.
	signed bool
}

// errVolumeNotValidated reports a volume asked for a header before its
// signature was consumed. Unexported: it is unreachable through the public
// API by construction, and an exported sentinel would be a contract this
// library has to hold forever for a state a caller cannot produce.
var errVolumeNotValidated = errors.New("rarengine: volume used before its signature was read")

var rar5Signature = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}

// signatureReadError names a volume that ended inside its own signature.
//
// io.ReadFull reports a stream holding nothing at all as bare io.EOF, which
// travels all the way out of NextEntry as "the archive is over" -- so an
// empty volume ended the traversal and every volume behind it went unread,
// with the caller told the set was complete. A zero-length part is an
// ordinary way for a download to fail, which is exactly why it must not be
// indistinguishable from the end of the archive.
func signatureReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: volume ended inside its signature", io.ErrUnexpectedEOF)
	}
	return err
}

// newVolume wraps rc as the Reader's open volume WITHOUT consuming anything
// from it. The stream is positioned at byte 0 -- v.readSignature must run
// before v.next(), and v.signed is what enforces that.
//
// Split from the signature read so a volume becomes reachable from the Reader
// at the instant its stream is received, rather than after a blocking read
// that Reader.Close could not reach. See nextVolume.
func newVolume(rc io.ReadCloser) *volume {
	return &volume{rc: rc}
}

// readSignature consumes and validates the RAR5 signature on v's own stream,
// leaving v positioned on the first block boundary.
//
// A failure here does not set v.err: v.err means "v.rc is at an offset next()
// cannot vouch for", and a volume that failed its signature is discarded by
// its caller rather than retried. Setting it would be harmless but would
// claim a sticky position-level failure this is not.
func (v *volume) readSignature() error {
	if err := readSignature(v.rc); err != nil {
		return err
	}
	v.signed = true
	return nil
}

// openVolume reads and validates the RAR5 signature, leaving v positioned on
// the first block boundary. A RAR3 signature is recognised only so it can be
// reported as ErrUnsupportedFormat by name; nothing past the signature is
// parsed.
func openVolume(rc io.ReadCloser) (*volume, error) {
	v := newVolume(rc)
	if err := v.readSignature(); err != nil {
		return nil, err
	}
	return v, nil
}

// readSignature consumes the RAR signature from r, leaving it positioned on
// the first block boundary.
//
// Split out of openVolume so the inspection entry points in inspect.go reach
// the stream the same way traversal does. A caller must never be asked to skip
// the signature itself: its length depends on which format the bytes turn out
// to be -- 7 for RAR3, 8 for RAR5 -- so "skip 8 and start parsing" silently
// mis-frames every RAR3 archive it is handed.
func readSignature(r io.Reader) error {
	var sig [8]byte
	if _, err := io.ReadFull(r, sig[:7]); err != nil {
		return signatureReadError(err)
	}
	if !bytes.Equal(sig[:6], rar5Signature[:6]) {
		return fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	switch sig[6] {
	case 0x00:
		return fmt.Errorf("%w: RAR3", ErrUnsupportedFormat)
	case 0x01:
		if _, err := io.ReadFull(r, sig[7:]); err != nil {
			return signatureReadError(err)
		}
		if sig[7] != 0x00 {
			return fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
		}
	default:
		return fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	return nil
}

// next skips whatever remains of the current block's payload, then reads the
// following header. io.EOF means this volume is exhausted.
//
// A short skip is not an error here. When a volume is truncated the promised
// bytes are simply absent, io.Copy stops at the underlying EOF, and the header
// read below then fails -- which is the same signal as a volume that simply
// ended, and is handled in one place by the caller.
//
// Once next() has failed, it keeps failing with the same error and never
// touches v.rc again -- see the err field's comment for why a failed read
// cannot safely be retried.
func (v *volume) next() (*blockHeader, error) {
	if !v.signed {
		return nil, errVolumeNotValidated
	}
	if v.err != nil {
		return nil, v.err
	}
	if _, err := io.Copy(io.Discard, &v.body); err != nil {
		v.err = err
		return nil, err
	}
	// io.Copy reports a source that ended early as success, so the skip
	// completing says nothing about whether the bytes were there. What the
	// block declared and what the volume held is the difference below: a
	// volume cut inside a payload leaves the next header to be read out of
	// whatever follows the cut, which is nothing this type can vouch for.
	if v.body.N > 0 {
		v.err = fmt.Errorf("%w: volume ended %d bytes inside a block's payload",
			io.ErrUnexpectedEOF, v.body.N)
		return nil, v.err
	}
	var (
		h   *blockHeader
		err error
	)
	if v.hd != nil {
		h, err = v.hd.readEncryptedBlockHeader(v.rc)
	} else {
		h, err = readBlockHeader(v.rc)
	}
	if err != nil {
		v.err = err
		return nil, err
	}
	v.body = io.LimitedReader{R: v.rc, N: h.DataSize}
	return h, nil
}

// payload is the current block's declared bytes, bounded by DataSize. A
// decoder handed this cannot read into the following header.
//
// The returned reader aliases v.body, which the next next() call re-points to
// describe a different block. It is only valid until that call: hold it
// across a next() and it silently starts producing the following block's
// payload instead of erroring, because the alias keeps working -- it just
// stops meaning what the caller thinks it means.
func (v *volume) payload() io.Reader { return &v.body }

// bodyShort reports that the block's declared payload was not all there.
// Only meaningful once payload() has reported io.EOF: before that it is
// simply how many bytes are still to come.
func (v *volume) bodyShort() bool { return v.body.N > 0 }

// useEncryptedHeaders switches next() to the decrypting header path, once an
// encryption header has yielded a key.
//
// It lives here rather than beside the traversal because "how a header is
// read" is the volume's business, and making it a per-call-site choice is the
// shape this type exists to remove. The key does not carry across a volume
// boundary: a new volume is a new value with hd nil, so header-encrypted
// multi-volume archives fail to parse rather than being misparsed.
func (v *volume) useEncryptedHeaders(key []byte) {
	v.hd = &headerDecrypter{key: key}
}

// Close closes the underlying stream once, and mutates nothing the traversal
// reads: rc and body are untouched. It does write the closeOnce/closeErr pair,
// which is ordered for every caller by the Once itself -- see that field.
//
// It used to nil v.rc and zero v.body, which is what made Reader.Close racy:
// those are fields the traversal reads and writes, and Reader.Close is the one
// method another goroutine may call. Leaving rc immutable after construction
// means a concurrent Close reads it safely, and leaving body alone means only
// the traversal ever writes it.
//
// What the body-zeroing used to guarantee -- that an Entry the caller still
// holds stops producing content -- is now the Reader's done channel, read
// through Entry.cancelled. That is strictly more than the zeroing covered: the
// zeroing sat below decoder50's window, so a compressed member kept delivering
// buffered plaintext after it.
func (v *volume) Close() error {
	v.closeOnce.Do(func() {
		if v.rc != nil {
			v.closeErr = v.rc.Close()
		}
	})
	return v.closeErr
}
