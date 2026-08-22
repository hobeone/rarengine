package rarengine

import (
	"errors"
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

	// solid reports whether the archive header declared a solid archive. It
	// decides whether abandoning a member must decode its remainder to keep
	// the window valid for a successor -- see NextEntry.
	solid bool
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
	r.resolved, r.hasResolved = "", false
	r.solid = false
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
	if err := r.finishActive(); err != nil {
		return nil, err
	}
	for {
		if r.vol == nil {
			if err := r.nextVolume(); err != nil {
				return nil, err
			}
		}
		h, err := r.vol.next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				_ = r.vol.Close()
				r.vol = nil
				continue
			}
			return nil, err
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
func (r *Reader) finishActive() error {
	e := r.entry
	r.entry = nil
	if e == nil {
		return nil
	}
	if r.solid {
		_ = e.Close()
	}
	if e.short() || (e.done != nil && !errors.Is(e.done, io.EOF) &&
		!errors.Is(e.done, ErrChecksumUnsupported)) {
		r.win.MarkIncomplete()
	}
	return nil
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
			return nil, nil // the block is skipped; the archive may still parse
		}
		r.solid = r.solid || ah.Solid
		return nil, nil

	case HeaderTypeFile:
		fh, err := ParseFileHeader(h)
		if err != nil {
			// Skipped rather than terminal. Under the previous design nothing
			// could say where the stream was after a failed parse, so this
			// ended the traversal; volume.next() answers that now.
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
		splicer := &volumeSplicer{r: r, e: e, src: r.vol.payload()}
		src, err := r.buildChain(fh, splicer)
		if err != nil {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err), nil
		}
		e.src = src
		r.entry = e
		return e, nil

	case HeaderTypeEncryption:
		ch, err := ParseCryptHeader(h)
		if err != nil {
			return nil, nil
		}
		password, err := r.resolveHeaderPassword(ch)
		if err != nil {
			// Every header after this one is ciphertext, so there is no member
			// to name and nothing to continue to. Archive-level.
			return nil, err
		}
		key, err := headerKeyFromPassword(ch, password)
		if err != nil {
			return nil, err
		}
		r.vol.useEncryptedHeaders(key)
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
//	       └─ volumeSplicer
//
// Decryption sits BELOW the splice so one CBC reader carries its chaining
// state across a volume boundary; see volumeSplicer for why that matters.
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
