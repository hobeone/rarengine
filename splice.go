package rarengine

import (
	"errors"
	"fmt"
	"io"
)

// multiVolumePayloadReader presents a member's payload as one continuous
// stream across the volumes it spans.
//
// It sits BELOW decryption in the chain, not above it. A member's ciphertext
// is one continuous CBC stream that volume boundaries cut at arbitrary
// offsets, with no per-volume IV to restart from -- the header repeats the
// first part's salt and IV unchanged. Splicing above the decryption fed each
// new volume's raw bytes straight to the decoder, so the first part decoded
// and every part after it was ciphertext.
type multiVolumePayloadReader struct {
	r   *Reader
	e   *Entry
	src io.Reader
}

func (s *multiVolumePayloadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err := s.src.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			// The header in force says whether this is the member's final
			// block; anything else means the payload continues in the next
			// volume, so an inner EOF is a boundary rather than an end.
			if s.e.lastBlock() {
				return 0, io.EOF
			}
			next, nextErr := s.r.nextVolumePayload(s.e)
			if nextErr != nil {
				return 0, nextErr
			}
			s.src = next
			continue
		}
		return 0, err
	}
}

// nextVolumePayload advances to the volume holding the member's continuation
// and returns its payload.
//
// It scans past whatever the new volume opens with -- its own archive header,
// service records -- because volume.next() skips each block's declared payload
// on the way to the following header. Nothing here has to discard.
func (r *Reader) nextVolumePayload(e *Entry) (io.Reader, error) {
	if err := r.nextVolume(); err != nil {
		return nil, err
	}
	for {
		h, err := r.vol.next()
		if err != nil {
			// This loop and NextEntry's must agree about what an exhausted
			// volume means, or a member spanning volumes 1->3 whose middle
			// volume carries no continuation block (nothing but its own
			// archive header, or an end header) dies here instead of
			// advancing to volume 3. NextEntry treats io.EOF/
			// io.ErrUnexpectedEOF from vol.next() as "this volume is spent,
			// open the next one and keep scanning" -- so this must too. The
			// old engine got this for free from an explicit HeaderTypeEnd
			// case in processVolumePayloadHeader that called nextVolume()
			// itself; that case does not exist here, because end headers
			// now fall through the same generic "not a file header, keep
			// scanning" path as everything else. That is correct for
			// payload accounting (volume.next() already dropped the
			// declared bytes) but it silently dropped the volume advance
			// the old case also provided.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				_ = r.vol.Close()
				r.vol = nil
				if verr := r.nextVolume(); verr != nil {
					// Do not translate to io.EOF: reaching here means a read
					// already in progress could not find its continuation,
					// so the member is unfinished. Entry.Read turns this
					// into the member's verdict (ErrTruncatedFile), the same
					// as it would for any other short read -- reporting a
					// clean end of stream here would be exactly the
					// truncation-as-success decay that sentinel exists to
					// prevent.
					return nil, verr
				}
				continue
			}
			return nil, err
		}
		if h.Type != HeaderTypeFile {
			if h.Type == HeaderTypeArchive {
				if ah, aerr := ParseArchiveHeader(h); aerr == nil {
					r.solid = r.solid || ah.Solid
				}
			}
			continue
		}
		fh, err := ParseFileHeader(h)
		if err != nil {
			return nil, err
		}
		if fh.FirstBlock {
			// A new member where a continuation was expected: the member in
			// progress has no more parts, so it ended short.
			return nil, io.EOF
		}
		// A per-file header flag must be re-checked on every volume advance,
		// not only at admission. This path builds no chain -- it feeds bytes
		// into the one the first block established -- so a continuation
		// claiming encryption the first block did not had this volume's
		// ciphertext delivered verbatim as content, with a nil error and a
		// header reporting Encrypted false. The inverse decrypts bytes that
		// were never ciphertext.
		if fh.Encrypted != e.Header.Encrypted {
			return nil, fmt.Errorf("%w: file %q: continuation declares "+
				"Encrypted=%v, first block declared %v",
				ErrCorruptFileHeader, e.Header.Name, fh.Encrypted, e.Header.Encrypted)
		}
		// Captures the whole-file CRC32, LastBlock and UseMac, all of which
		// RAR records on the LAST part rather than the first.
		e.advanceVolume(fh)
		return r.vol.payload(), nil
	}
}
