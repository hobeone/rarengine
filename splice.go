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
			// Unless the volume was cut inside the payload it declared. The
			// LimitedReader reports EOF either way, so without this the
			// missing bytes were stitched over with the next volume's
			// continuation and the member completed -- reporting success for
			// content it never received, or a CRC mismatch that names the
			// wrong cause.
			// r.vol is nil only if the Reader was reset out from under this
			// member, which severs it before it can read -- the check is
			// here because "not short" is the right answer for a volume that
			// no longer exists, not because the state is reachable.
			if s.r.vol != nil && s.r.vol.bodyShort() {
				return 0, fmt.Errorf("%w: file %q: volume ended inside its payload",
					io.ErrUnexpectedEOF, s.e.Header.Name)
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
	if err := r.openNextVolume(); err != nil {
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
				// A volume cut inside some OTHER block -- an end header
				// claiming a payload it does not carry, say -- is spent, not
				// disqualifying: this member's own bytes are whole in the
				// volumes either side of it, and multiVolumePayloadReader.Read
				// is what refuses a cut through THIS member's payload. So the
				// scan advances, and only records that the set is damaged.
				if !errors.Is(err, io.EOF) {
					r.damaged = err
				}
				_ = r.vol.Close()
				r.vol = nil
				if verr := r.openNextVolume(); verr != nil {
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
			if h.Type == HeaderTypeEnd {
				// Same rule the scan follows: no block after this one belongs
				// to the archive, so the continuation is not in this volume
				// and reading further here would parse whatever padding
				// follows.
				_ = r.vol.Close()
				r.vol = nil
				if verr := r.openNextVolume(); verr != nil {
					return nil, r.latchArchive(verr)
				}
				continue
			}
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
		fh, err := parseFileHeader(h)
		if err != nil {
			if fh != nil && fh.FirstBlock {
				// A new member whose header failed to parse. Its bytes are
				// not this member's continuation, so the member in progress
				// ended short -- and the new member is staged rather than
				// dropped, exactly as an intact new member is below. The
				// exported ParseFileHeader stood here and discards the
				// header it built, so this branch could not exist: the new
				// member's failure was reported as the spliced member's, and
				// nextEntry then skipped the block entirely, losing a member
				// that dispatch would have refused by name.
				r.staged = h
				return nil, io.EOF
			}
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
		// Same rule, applied to what says this is the same member's bytes at
		// all. Nothing but the !FirstBlock flag connected a continuation to
		// the member it was spliced into, so volumes presented out of order,
		// or an archive built to interleave two members, had another file's
		// payload delivered as this one's content -- and a method mismatch
		// fed compressed bytes to the store reader that the first block
		// selected, or the reverse.
		if fh.Name != e.Header.Name || fh.Method != e.Header.Method {
			return nil, fmt.Errorf("%w: file %q: continuation declares name %q "+
				"method %d, first block declared name %q method %d",
				ErrCorruptFileHeader, e.Header.Name, fh.Name, fh.Method,
				e.Header.Name, e.Header.Method)
		}
		// Captures the whole-file CRC32, LastBlock and UseMac, all of which
		// RAR records on the LAST part rather than the first.
		e.advanceVolume(fh)
		return r.vol.payload(), nil
	}
}
