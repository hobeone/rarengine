package rarengine

import (
	"bytes"
	"fmt"
	"io"
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
}

var rar5Signature = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}

// openVolume reads and validates the RAR5 signature, leaving v positioned on
// the first block boundary. A RAR3 signature is recognised only so it can be
// reported as ErrUnsupportedFormat by name; nothing past the signature is
// parsed.
func openVolume(rc io.ReadCloser) (*volume, error) {
	var sig [8]byte
	if _, err := io.ReadFull(rc, sig[:7]); err != nil {
		return nil, err
	}
	if !bytes.Equal(sig[:6], rar5Signature[:6]) {
		return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	switch sig[6] {
	case 0x00:
		return nil, fmt.Errorf("%w: RAR3", ErrUnsupportedFormat)
	case 0x01:
		if _, err := io.ReadFull(rc, sig[7:]); err != nil {
			return nil, err
		}
		if sig[7] != 0x00 {
			return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
		}
	default:
		return nil, fmt.Errorf("%w: bad signature", ErrUnsupportedFormat)
	}
	return &volume{rc: rc}, nil
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
func (v *volume) next() (*BlockHeader, error) {
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
	if v.rc == nil {
		v.err = fmt.Errorf("rarengine: next called on a closed volume")
		return nil, v.err
	}
	var (
		h   *BlockHeader
		err error
	)
	if v.hd != nil {
		h, err = v.hd.readEncryptedBlockHeader(v.rc)
	} else {
		h, err = ReadBlockHeader(v.rc)
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

func (v *volume) Close() error {
	if v.rc == nil {
		return nil
	}
	err := v.rc.Close()
	v.rc = nil
	v.body = io.LimitedReader{}
	return err
}
