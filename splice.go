package rarengine

import (
	"fmt"
	"io"
)

// volumeSplicer presents a member's payload as one continuous stream across
// the volumes it spans.
//
// It sits BELOW decryption in the chain, not above it. A member's ciphertext
// is one continuous CBC stream that volume boundaries cut at arbitrary
// offsets, with no per-volume IV to restart from -- the header repeats the
// first part's salt and IV unchanged. Splicing above the decryption fed each
// new volume's raw bytes straight to the decoder, so the first part decoded
// and every part after it was ciphertext.
type volumeSplicer struct {
	r   *Reader
	e   *Entry
	src io.Reader
}

func (s *volumeSplicer) Read(p []byte) (int, error) {
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
