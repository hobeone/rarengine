package rarengine

import (
	"errors"
	"fmt"
	"io"
)

// Reader is a sequential, tar-like reader over a RAR5 archive delivered as a
// channel of volumes.
//
// It owns the volume chain and block dispatch. It does NOT own where the
// stream is -- volume does -- and it does not own how a member ended -- Entry
// does. What is left here is genuinely traversal: which volume, which block,
// and whether a member may begin.
type Reader struct {
	volumes <-chan io.ReadCloser

	// vol is nil whenever no volume is open, including after every failure.
	// Because an advance constructs a new volume rather than repointing one, a
	// failed advance cannot leave a partially consumed volume reachable.
	vol *volume

	win   *Window
	entry *Entry
	dec50 *decoder50

	passwords []string
	// resolved is the candidate that verified against the archive's check
	// value, latched so the cost is one derivation per candidate per archive
	// rather than per member.
	resolved    string
	hasResolved bool

	// staged holds a block header that was read while scanning for something
	// else and must not be lost. nextVolumePayload (splice.go) reads headers
	// looking for a member's continuation; when it finds a NEW member instead,
	// that member's header has already been consumed from the volume and the
	// volume cannot rewind. Without staging it here, the next nextEntry call
	// would ask the volume for a header, volume.next() would skip the staged
	// member's declared payload on its way to the following block, and the
	// member would be lost from the traversal entirely with the archive
	// reporting a clean end.
	//
	// The invariant that makes this safe: staged is only ever set immediately
	// after the volume.next() call that produced it, so r.vol.payload() still
	// describes exactly that header's body. Nothing may advance the volume
	// between setting staged and consuming it.
	staged *BlockHeader

	// damaged remembers a volume that ended somewhere this traversal cannot
	// vouch for -- inside a block's declared payload, or partway through a
	// header. Scanning continues past it, because the members in the volumes
	// beyond the cut are still readable and a set arriving with a part
	// missing is ordinary rather than exceptional. What it must not do is
	// call the archive finished CLEANLY afterwards: this is reported in
	// io.EOF's place once the volumes run out, so a caller looping until
	// io.EOF cannot mistake a set with a hole in it for a complete one.
	damaged error

	// solid reports whether the archive header declared a solid archive. It
	// decides whether abandoning a member must decode its remainder to keep
	// the window valid for a successor -- see NextEntry.
	solid bool

	// fatal is sticky once set: NextEntry checks it first and, if non-nil,
	// returns it again without touching r.vol. It is set by NextEntry itself
	// -- never by dispatch or any other helper -- for exactly the errors
	// that leave r.vol non-nil after a failure. Those are the ones where the
	// stream is left positioned past a block whose bytes were consumed but
	// not trusted (a malformed archive header, a header-encryption failure):
	// r.vol itself has no memory of the failure, so a retry would call
	// r.vol.next() again and parse the following bytes as a fresh header,
	// which is exactly the fabricated-entry risk this field exists to close.
	//
	// It deliberately does NOT latch io.EOF or ErrNoNextVolume: both are
	// ordinary end-of-archive signals, not failures, and nextVolume already
	// leaves r.vol nil on every one of its own failure paths -- including
	// ErrNoNextVolume -- so a retry there starts fresh on the next channel
	// volume rather than resuming into anything fabricated. It also does not
	// need to latch a non-EOF error from r.vol.next(): volume.err is already
	// sticky (see volume's err field), so that error is self-latching
	// without r.vol ever being retried into unread bytes.
	fatal error
}

// NewReader constructs a Reader over volumes, allocating the 32 MB window.
func NewReader(volumes <-chan io.ReadCloser) *Reader {
	return &Reader{
		volumes: volumes,
		win:     NewWindow(32 * 1024 * 1024),
		dec50:   newDecoder50(),
	}
}

// Reset reconfigures the reader for a new archive, reusing the 32 MB window.
// Nothing else survives: a verdict, a resolved password and a damaged window
// all belong to the archive that produced them.
func (r *Reader) Reset(volumes <-chan io.ReadCloser) {
	if r.vol != nil {
		_ = r.vol.Close()
		r.vol = nil
	}
	r.volumes = volumes
	r.entry = nil
	r.staged = nil
	r.damaged = nil
	r.resolved, r.hasResolved = "", false
	r.solid = false
	r.fatal = nil
	// BeginFile(false) is the window's one entrance for discarding history: it
	// resets the pointers and clears incomplete together. Poking r.win.incomplete
	// directly here would reintroduce a second writer of that flag, which is
	// exactly what Window.BeginFile/MarkIncomplete exist to prevent.
	_ = r.win.BeginFile(false)
}

// SetPasswords supplies candidate passwords, tried in order against the
// archive's password check value. RAR5 only.
func (r *Reader) SetPasswords(candidates []string) { r.passwords = candidates }

// NextEntry finishes any active entry, scans forward, and returns the next
// member. io.EOF reports that the archive is over.
//
// Its errors are archive-level only -- a malformed block header, no next
// volume, an unsupported format, end of stream. Every per-member outcome is
// delivered by the Entry, including refusals, which arrive as an Entry that is
// already terminal.
func (r *Reader) NextEntry() (*Entry, error) {
	if r.fatal != nil {
		return nil, r.fatal
	}
	e, err := r.nextEntry()
	if err != nil {
		return nil, r.latchArchive(err)
	}
	// A latch set DURING this call must not be outrun by whatever the scan
	// went on to find. finishActive drains an abandoned solid member through
	// the splice, which reaches every archive-level failure nextVolumePayload
	// latches -- a corrupt archive header in the continuation volume, say --
	// and it discards that error because its own result is the member's, not
	// the archive's. The scan loop then read the bytes after that untrusted
	// header and dispatch built a member out of them, which was returned with
	// a nil error because latchArchive(nil) never consults r.fatal. The latch
	// only bit on the following call, one fabricated member too late.
	if r.fatal != nil {
		return nil, r.fatal
	}
	return e, nil
}

// armHeaderDecryption switches the current volume onto the decrypting header
// path from a HEAD_CRYPT block.
//
// Shared by dispatch and nextVolumePayload (splice.go) because EVERY volume of
// a header-encrypted archive repeats its own HEAD_CRYPT in plaintext, and each
// volume is a fresh value with its own nil decryptor -- openVolume carries
// nothing forward. Handling it in only one of the two header-reading paths
// left a member spanning a volume boundary reading volume two's ciphertext as
// plaintext, which surfaced as ErrBadHeaderCRC partway through the file.
//
// Every failure here is archive-level: once a HEAD_CRYPT is present, every
// header after it is ciphertext this library cannot read, so there is no
// member to name and nothing to continue to. Callers latch what this returns.
func (r *Reader) armHeaderDecryption(h *BlockHeader) error {
	ch, err := ParseCryptHeader(h)
	if err != nil {
		// Classified so a caller can tell "this archive uses an encryption
		// version this library does not implement" -- the archive need not be
		// damaged -- from "this header is corrupt", while errors.Is still
		// reaches the underlying parse failure through either wrap.
		if errors.Is(err, ErrUnknownEncryptMethod) {
			return fmt.Errorf("%w: %w", ErrUnsupportedEncryptionVersion, err)
		}
		return fmt.Errorf("%w: %w", ErrCorruptArchiveHeader, err)
	}
	password, err := r.resolveHeaderPassword(ch)
	if err != nil {
		return err
	}
	key, err := headerKeyFromPassword(ch, password)
	if err != nil {
		return err
	}
	r.vol.useEncryptedHeaders(key)
	return nil
}

// latchArchive records err on r.fatal, unless it is one of the ordinary
// end-of-archive signals (io.EOF, ErrNoNextVolume), and returns err
// unchanged so a call site can wrap a return in one expression.
//
// This is the one place that decides which errors are archive-level enough
// to end traversal for the rest of this Reader's life -- NextEntry uses it
// for its own scan loop, and nextVolumePayload (splice.go) uses it for the
// same failures reached while splicing a member across a volume boundary.
// Both leave r.vol nil already on every failure path (see nextVolume and the
// fatal field's comment), so retrying an unlatched error resumes cleanly
// rather than resuming past an unresolved failure -- there is nothing here
// for the latch to guard on io.EOF or ErrNoNextVolume.
//
// ErrNoNextVolume is deliberately never latched: reached while a read is
// already in progress it means only that THIS member is unfinished (the
// channel closed before its continuation arrived), not that the archive
// itself is corrupt. Latching it would stop TestReader_RealArchive_
// MissingFinalVolume's traversal from ending cleanly afterwards -- the next
// NextEntry call is expected to find the channel closed on its own and
// report end of archive, not replay a stale fatal error.
func (r *Reader) latchArchive(err error) error {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrNoNextVolume) {
		r.fatal = err
	}
	return err
}

// nextEntry is NextEntry's scan loop, unlatched: every error it returns is
// evaluated by NextEntry for whether it should end traversal for the rest of
// this Reader's life. Nothing below this point may be called except through
// NextEntry.
func (r *Reader) nextEntry() (*Entry, error) {
	r.finishActive()
	for {
		var h *BlockHeader
		if r.staged != nil {
			// Consumed before the volume is touched: volume.next() would skip
			// this header's payload on the way to the next block. See
			// Reader.staged.
			h, r.staged = r.staged, nil
		} else {
			if r.vol == nil {
				if err := r.nextVolume(); err != nil {
					// Running out of volumes with no member in progress is
					// the archive being over, which NextEntry reports as
					// io.EOF -- the one thing its doc comment promises.
					// ErrNoNextVolume keeps its meaning where it is a
					// failure: reached mid-member, through the splice, it is
					// that member's verdict and says a part is missing.
					if errors.Is(err, ErrNoNextVolume) {
						if r.damaged != nil {
							return nil, r.damaged
						}
						return nil, io.EOF
					}
					return nil, err
				}
			}
			var err error
			h, err = r.vol.next()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					if !errors.Is(err, io.EOF) {
						r.damaged = err
					}
					_ = r.vol.Close()
					r.vol = nil
					continue
				}
				return nil, err
			}
		}
		e, err := r.dispatch(h)
		if err != nil {
			return nil, err
		}
		if e != nil {
			return e, nil
		}
	}
}

// finishActive ends the member in progress before the traversal moves on.
//
// Abandoning a member costs a decode only when the archive is solid, because
// that is the only case where a successor's back-references reach into what
// this member should have written. In a non-solid archive volume.next() skips
// the raw packed bytes instead, which is why listing an archive's members no
// longer decompresses it.
//
// Either way a member that did not reach its declared size marks the window
// incomplete, so a solid successor is refused rather than decoded against
// history nobody wrote.
func (r *Reader) finishActive() {
	e := r.entry
	r.entry = nil
	if e == nil {
		return
	}
	if r.solid {
		_ = e.Close()
	} else {
		// Sever before anything can read through it. e.src bottoms out on the
		// volume's aliased v.body, which the next v.next() call re-points to
		// describe a following block; an abandoned Entry that still holds it
		// would silently start serving that block's bytes with a nil error
		// instead of reporting its own truncation. Cutting the source here,
		// rather than decoding to completion, is what keeps a non-solid
		// abandon cheap -- see the doc comment above.
		e.src = nil
		if e.done == nil {
			if e.short() {
				_ = e.finish(e.truncated())
			} else {
				_ = e.finish(nil)
			}
		}
	}
	if e.short() || (e.done != nil && !errors.Is(e.done, io.EOF) &&
		!errors.Is(e.done, ErrChecksumUnsupported)) {
		r.win.MarkIncomplete()
	}
}

// dispatch consumes one block and reports what it was.
//
// A nil Entry with a nil error means the block held nothing the caller wants
// and scanning continues. Nothing here discards payload: volume.next() does
// that on the way to the following header, unconditionally, whether or not any
// case below looked at the block.
func (r *Reader) dispatch(h *BlockHeader) (*Entry, error) {
	switch h.Type {
	case HeaderTypeArchive:
		ah, err := ParseArchiveHeader(h)
		if err != nil {
			// Fatal, not skipped. The archive header occurs once per volume
			// and defines archive-wide semantics, including whether the
			// archive is solid. NextEntry's error set is explicitly
			// archive-level, and a header this library cannot parse is
			// precisely an archive-level problem: continuing past it means
			// proceeding with unknown archive-wide semantics. Wrapped so a
			// caller can alarm on ErrCorruptArchiveHeader specifically while
			// errors.Is still reaches the underlying parse failure -- see
			// ErrCorruptArchiveHeader's doc comment. NextEntry latches this
			// (see Reader.fatal) so a second call cannot resume past it.
			return nil, fmt.Errorf("%w: %w", ErrCorruptArchiveHeader, err)
		}
		r.solid = r.solid || ah.Solid
		return nil, nil

	case HeaderTypeFile:
		fh, err := parseFileHeader(h)
		if err != nil {
			// A member whose identity survived the failure is refused by NAME,
			// so the caller learns the archive held something it could not
			// read. One that failed before its name was decoded has nothing to
			// report and is skipped as before. Either way volume.next() drops
			// the block's declared payload on the way to the next header.
			if fh != nil && fh.FirstBlock {
				r.win.MarkIncomplete()
				return terminalEntry(fh, err), nil
			}
			// Damage is recorded from what happened to the file, never from
			// what the caller is told about it. A member skipped here is one
			// whose name was never decoded, so nothing can be reported -- but
			// it still contributed no bytes, and a solid successor's
			// back-references assume otherwise. Marking only the named path
			// left exactly the unreportable failures decoding a successor
			// against history nobody wrote.
			if fh == nil || fh.FirstBlock {
				r.win.MarkIncomplete()
			}
			return nil, nil
		}
		// A continuation block belongs to a member already announced. Reaching
		// one here means that member was abandoned, so it is skipped like any
		// other unclaimed block.
		if !fh.FirstBlock {
			return nil, nil
		}
		if fh.UnpackedSize > 1024*1024 && fh.UnpackedSize > 1000*fh.PackedSize {
			r.win.MarkIncomplete()
			return terminalEntry(fh, ErrRarBombDetected), nil
		}
		if err := r.win.BeginFile(fh.Solid); err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		// e is built before the splicer, and the splicer before the decode
		// chain, because the splicer consults e through lastBlock() while
		// reading -- both must exist before the chain's first Read. e.src is
		// filled in only once the chain is known to build successfully.
		e := newEntry(fh, nil)
		splicer := &multiVolumePayloadReader{r: r, e: e, src: r.vol.payload()}
		src, err := r.buildChain(fh, splicer)
		if err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		e.src = src
		r.entry = e
		return e, nil

	case HeaderTypeEncryption:
		if err := r.armHeaderDecryption(h); err != nil {
			return nil, err
		}
		return nil, nil

	default:
		// Everything the caller never sees, including service records -- quick
		// open, comment, recovery, ACL, stream. Those reuse the file-header
		// layout, so routing them to the file case would surface one as a
		// member named after the record and hand its bytes over as content.
		return nil, nil
	}
}

// resolvePassword picks the candidate that matches the member's password check
// value, latching it for the rest of the archive.
//
// The check value is a fold of the PBKDF2 chain, so a candidate is tested
// without decrypting or decompressing anything. Latching means the cost is one
// derivation per candidate per archive rather than per member.
//
// A member carrying no check value cannot have a candidate verified this way,
// so passwords[0] is used for that member WITHOUT setting hasResolved. That
// distinction is deliberate: a candidate verified against a real check value
// is knowledge -- it cannot be wrong for this archive -- and knowledge is what
// justifies skipping the scan for every later member. An unverified first
// guess is only a default for a member that offered nothing to check it
// against; caching it as though it were knowledge would suppress the scan for
// a later member that DOES carry a check value, silently losing the archive
// to whichever candidate happens to sort first whenever the first encrypted
// member's check value is absent.
func (r *Reader) resolvePassword(fh *FileHeader) (string, error) {
	if r.hasResolved {
		return r.resolved, nil
	}
	if len(r.passwords) == 0 {
		return "", ErrPasswordRequired
	}
	if fh.EncCheck == nil {
		return r.passwords[0], nil
	}
	for _, candidate := range r.passwords {
		ok, hasCheck, err := VerifyFilePassword(fh, candidate)
		if err != nil {
			return "", err
		}
		if !hasCheck {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
		if ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}

// resolveHeaderPassword is resolvePassword for archive-level header
// encryption, whose check value lives on the CryptHeader rather than on a file
// header.
func (r *Reader) resolveHeaderPassword(ch *CryptHeader) (string, error) {
	if r.hasResolved {
		return r.resolved, nil
	}
	if len(r.passwords) == 0 {
		return "", ErrPasswordRequired
	}
	for _, candidate := range r.passwords {
		ok, hasCheck, err := VerifyPassword(ch, candidate)
		if err != nil {
			return "", err
		}
		if !hasCheck || ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}

// buildChain assembles the decode chain for a member:
//
//	decoder50 / storeReader
//	  └─ cbcDecryptReader (if encrypted)
//	       └─ multiVolumePayloadReader
//
// Decryption sits BELOW the splice so one CBC reader carries its chaining
// state across a volume boundary; see multiVolumePayloadReader for why that
// matters.
func (r *Reader) buildChain(fh *FileHeader, src io.Reader) (io.Reader, error) {
	if fh.Encrypted {
		password, err := r.resolvePassword(fh)
		if err != nil {
			return nil, err
		}
		const maxKdfCount = 24
		if fh.KdfCount > maxKdfCount {
			return nil, errKdfCountExceeded(fh.KdfCount, maxKdfCount)
		}
		key, pswCheckVal := pbkdf2HmacSha256([]byte(password), fh.Salt, 1<<fh.KdfCount)
		if fh.EncCheck != nil {
			if err := verifyEncCheck(pswCheckVal, fh.EncCheck); err != nil {
				return nil, err
			}
		}
		decSrc, err := newCBCDecryptReader(src, key, fh.IV)
		if err != nil {
			return nil, err
		}
		src = decSrc
	}
	if fh.Method == 0 {
		return &storeReader{r: src, win: r.win}, nil
	}
	r.dec50.init(src, fh.FirstBlock)
	return &lz50Reader{dec: r.dec50, win: r.win}, nil
}

type lz50Reader struct {
	dec *decoder50
	win *Window
}

func (l *lz50Reader) Read(p []byte) (int, error) {
	return l.dec.Read(l.win, p)
}

type storeReader struct {
	r   io.Reader
	win *Window
}

func (s *storeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.win.writeBytes(p[:n])
	}
	return n, err
}

// nextVolume closes the current volume and opens the next.
//
// Every failure leaves r.vol nil, which is a lifetime rather than a rule: the
// field is assigned the result, so a failed advance has nothing to leave
// behind. Under the previous design this had to be maintained by hand at each
// exit, and a volume left standing after a failure was read again at whatever
// offset the failure stopped at.
func (r *Reader) nextVolume() error {
	if r.vol != nil {
		_ = r.vol.Close()
		r.vol = nil
	}
	rc, ok := <-r.volumes
	if !ok {
		return ErrNoNextVolume
	}
	v, err := openVolume(rc)
	if err != nil {
		_ = rc.Close()
		return err
	}
	r.vol = v
	return nil
}
