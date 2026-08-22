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
}

var rar5Signature = []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}

// openVolume reads and validates the RAR5 signature, leaving v positioned on
// the first block boundary. A RAR3 signature is reported as
// ErrUnsupportedFormat: its headers stay parseable through
// ReadRAR3BlockHeader for callers that inspect archives, but there is no RAR3
// decoder to hand the volume to.
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
func (v *volume) next() (*BlockHeader, error) {
	if _, err := io.Copy(io.Discard, &v.body); err != nil {
		return nil, err
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
		return nil, err
	}
	v.body = io.LimitedReader{R: v.rc, N: h.DataSize}
	return h, nil
}

// payload is the current block's declared bytes, bounded by DataSize. A
// decoder handed this cannot read into the following header.
func (v *volume) payload() io.Reader { return &v.body }

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
