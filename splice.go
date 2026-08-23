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
			// A read that produced bytes AND failed must report both. io.EOF
			// is the exception: it may be a volume boundary rather than an
			// end, and the loop below decides which -- so it is swallowed
			// here and rediscovered on the next call, once these bytes have
			// been delivered. Any other error is real, and returning nil in
			// its place lost it entirely unless the underlying reader chose
			// to repeat it, which io.Reader does not require.
			if err != nil && !errors.Is(err, io.EOF) {
				return n, err
			}
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
		return nil, r.latchArchive(err)
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
					// already in progress could not find its continuation, so
					// the member is unfinished. Entry.Read records this as the
					// member's terminal verdict verbatim -- ErrNoNextVolume,
					// NOT ErrTruncatedFile -- and that distinction is the
					// point: it says the archive is missing a volume rather
					// than that this member ran short within one, which is
					// more than a truncation verdict can say. Reporting a
					// clean end of stream here would be the
					// truncation-as-success decay ErrTruncatedFile exists to
					// prevent; translating to ErrTruncatedFile would instead
					// discard which of the two happened.
					return nil, r.latchArchive(verr)
				}
				continue
			}
			return nil, r.latchArchive(err)
		}
		if h.Type != HeaderTypeFile {
			if h.Type == HeaderTypeEncryption {
				// Every volume of a header-encrypted archive repeats its own
				// HEAD_CRYPT in plaintext, and each volume is a fresh value
				// whose header decryptor starts nil. Skipping this block left
				// the rest of the volume's headers -- including the
				// continuation this loop is looking for -- read as plaintext
				// when they are ciphertext, which surfaced as
				// ErrBadHeaderCRC partway through a member that spanned the
				// boundary. Archive-level, so it latches like the archive
				// header below.
				if aerr := r.armHeaderDecryption(h); aerr != nil {
					return nil, r.latchArchive(aerr)
				}
				continue
			}
			if h.Type == HeaderTypeArchive {
				ah, aerr := ParseArchiveHeader(h)
				if aerr != nil {
					// Consistent with the identical failure reached
					// through NextEntry's own dispatch (reader.go): a
					// corrupt archive header is archive-level, not a
					// per-member outcome, and must end traversal the
					// same way whichever path finds it. Left lenient
					// here, an attacker could choose which path parses a
					// truncated archive header by putting it in a volume
					// a member continues into, rather than one NextEntry
					// scans directly.
					return nil, r.latchArchive(fmt.Errorf("%w: %w", ErrCorruptArchiveHeader, aerr))
				}
				r.solid = r.solid || ah.Solid
			}
			continue
		}
		fh, err := ParseFileHeader(h)
		if err != nil {
			// Member-level, not archive-level: volume.next() has already
			// drained the previous block and will drop this one's unclaimed
			// payload on its way to the following header, so the stream is
			// standing somewhere vouchable and the members behind this one
			// are still readable. Latching it here ended the whole archive
			// for one member's corrupt continuation -- and dispatch treats
			// the identical failure as a per-member outcome, so latching was
			// also the two paths disagreeing about the same header. The
			// encryption-claim check below returns member-level for the same
			// reason.
			return nil, err
		}
		if fh.FirstBlock {
			// A new member where a continuation was expected: the member in
			// progress has no more parts, so it ended short.
			//
			// This header has already been consumed from the volume, which
			// cannot rewind, so it is staged for the next nextEntry call.
			// Returning io.EOF without staging it dropped the new member
			// entirely: nextEntry would call volume.next(), which skips the
			// unclaimed payload of the block just read, and the archive
			// reported a clean end with a file silently missing.
			r.staged = h
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
