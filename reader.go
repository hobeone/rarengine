package rarengine

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
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

	// vol is the open volume, or nil when none is. An advance constructs a new
	// volume rather than repointing one, so a failed advance cannot leave a
	// partially consumed volume reachable: takeVolume clears the field before
	// the receive and publishVolume is the only thing that sets it, so there
	// is nothing for a failure to leave behind.
	//
	// Assigned in exactly two places, takeVolume and publishVolume, both on
	// the traversal goroutine and both under volMu -- so the field has ONE
	// writing goroutine rather than two synchronised ones, and Close's read is
	// ordered against every write. The check is
	// `grep -nE '^\s+r\.vol = ' reader.go splice.go` returning two lines --
	// anchored so it counts assignments rather than the prose in Close's doc
	// comment that mentions the one this change removed. volMu's comment and
	// takeVolume's point here rather than restating it.
	//
	// One exception, and it is deliberate: after Close this field keeps
	// pointing at a volume that has been CLOSED, because Close no longer
	// writes it. That is weaker than this codebase's usual preference for
	// unrepresentable over unreachable, and it buys the field a single writing
	// goroutine -- which is what made every unlocked read of it safe and what
	// removed a reachable nil dereference from dispatch. A traversal that
	// reaches the stale pointer reads a closed stream and gets that stream's
	// error, which Entry.finish and NextEntry both translate; it does not
	// panic, and it is not a data race.
	vol *volume

	win   *window
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
	staged *blockHeader

	// done is closed by Close. It is the escape from the volume receive,
	// which is otherwise unbounded: a Reader waiting for a volume that will
	// never arrive cannot rescue itself, because the only other thing that
	// ends that wait is the producer closing the channel.
	done chan struct{}

	// volMu orders the fields Close shares with the traversal: r.done,
	// r.volumes, and r.vol -- which Close only READS; see the vol field for
	// why that field has one writer rather than two synchronised ones. Taken
	// at volume transitions only, once per volume and never per byte.
	//
	// r.done is in here because Reset REPLACES it: a plain sync.Once would be
	// copied out from under a Close already inside its Do, letting a second Do
	// body run and close an already-closed channel, which panics. A field
	// replaced under a lock cannot be copied at the wrong moment, so the
	// hazard stops existing rather than being synchronised around. That is
	// also why Close tests the channel with chanClosed under this lock instead
	// of using the sync.Once io.Pipe uses -- a pipe is never reset.
	//
	// It does not make a volume's CONTENTS safe and does not need to: v.rc is
	// immutable after construction and v.body is written only by the
	// traversal, because volume.Close stopped mutating both.
	volMu sync.Mutex

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
		done:    make(chan struct{}),
		volumes: volumes,
		win:     newWindow(32 * 1024 * 1024),
		dec50:   newDecoder50(),
	}
}

// Reset reconfigures the reader for a new archive, reusing the 32 MB window.
// Nothing else survives: a verdict, a resolved password and a damaged window
// all belong to the archive that produced them.
func (r *Reader) Reset(volumes <-chan io.ReadCloser) {
	// First, and without reading anything: a member left in progress holds
	// the splicer, which asks the Reader for the next volume when it wants a
	// continuation. Clearing r.entry alone left that entry live, so a caller
	// reading or closing it after Reset -- a deferred Close is enough --
	// pulled volumes off the NEW channel and consumed headers the new
	// traversal had not seen.
	r.severActive()
	r.closeCurrentVolume()
	// The abandoned channel's queued volumes are closed here, or nothing ever
	// closes them: Reset is the caller saying it is done with that archive,
	// and the ReadClosers still sitting on its channel are as much a part of
	// it as the one that was open.
	r.volMu.Lock()
	old := r.volumes
	r.volMu.Unlock()
	// --- no lock held below this line ---
	drainVolumes(old)
	// A fresh done, so Reset revives a Reader that had been closed. Close is
	// terminal for an ARCHIVE, not for the Reader: reuse across archives is
	// what Reset exists for, and refusing to revive would mean allocating a
	// new 32 MB window to recover from a cancelled download.
	r.volMu.Lock()
	r.done = make(chan struct{})
	r.volumes = volumes
	r.volMu.Unlock()
	// --- no lock held below this line ---
	r.staged = nil
	r.damaged = nil
	r.resolved, r.hasResolved = "", false
	r.solid = false
	r.fatal = nil
	// BeginFile(false) is the window's one entrance for discarding history: it
	// resets the pointers and clears incomplete together. Poking r.win.incomplete
	// directly here would reintroduce a second writer of that flag, which is
	// exactly what window.BeginFile/MarkIncomplete exist to prevent.
	_ = r.win.BeginFile(false)
}

// SetPasswords supplies candidate passwords, tried in order against the
// archive's password check value. RAR5 only.
func (r *Reader) SetPasswords(candidates []string) { r.passwords = candidates }

// NextEntry finishes any active entry, scans forward, and returns the next
// member. io.EOF reports that the archive is over.
//
// Its errors are archive-level -- a malformed block header, no next volume,
// an unsupported format, end of stream -- plus ErrReaderClosed, which is not
// archive-level and is exactly why latchArchive excludes it: the caller closed
// this Reader, which is a statement about the caller rather than the archive.
// Every per-member outcome is delivered by the Entry, including refusals,
// which arrive as an Entry that is already terminal.
func (r *Reader) NextEntry() (*Entry, error) {
	// Checked before r.fatal and before any read, so a sequential
	// Close-then-NextEntry performs no read on the caller's stream at all.
	// A Close landing DURING this call is not caught here -- nothing at the
	// head of a call can be -- it is caught by the translation below.
	if r.isClosed() {
		return nil, ErrReaderClosed
	}
	if r.fatal != nil {
		return nil, r.fatal
	}
	e, err := r.nextEntry()
	if err != nil {
		// A Close that landed mid-scan. nextEntry's loop had already passed
		// the pre-check, so r.vol.next() went on to read a stream the caller
		// had closed underneath it, and err is whatever that stream said --
		// os.ErrClosed for an *os.File, which is what this library's consumers
		// actually feed. Reporting it would name the caller's own decision as
		// an archive failure AND latch it onto r.fatal for the Reader's life.
		//
		// This is os.File.wrapErr's move: translate the internal
		// "you closed this" into the caller-facing sentinel at the boundary.
		//
		// Unconditional, unlike Entry.finish's override, which fires only for
		// a SHORT member. A member's verdict may still be read after Close, so
		// it must stay true about the bytes delivered; this verdict only
		// decides whether traversal continues, and a closed Reader does not.
		//
		// The cause rides along as %v text rather than being discarded: a
		// corrupt archive header found while a Close is in flight is still a
		// corrupt archive header, and a caller reading a log wants to know.
		// %v and not %w, so this cannot make errors.Is(err, io.EOF) true for a
		// scan that ended on one -- callers loop until io.EOF.
		//
		// A guard at the head of the scan loop was tried instead and removed:
		// unreachable by any sequential test, and it changed no verdict once
		// this translation existed. See CLAUDE.md, "Cancellation is one
		// channel, checked above the decode chain".
		//
		// Not re-wrapped when the scan already reported cancellation --
		// nextVolume returns ErrReaderClosed from its done select and from
		// publishVolume's refusal -- which produced "reader is closed: scan
		// ended on: rarengine: reader is closed".
		if r.isClosed() {
			if errors.Is(err, ErrReaderClosed) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: scan ended on: %v", ErrReaderClosed, err)
		}
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
func (r *Reader) armHeaderDecryption(h *blockHeader) error {
	ch, err := parseCryptHeader(h)
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
//
// ErrReaderClosed is likewise never latched, for a different reason:
// r.fatal exists to stop traversal resuming past an unresolved ARCHIVE
// failure, and a closed Reader is not an archive failure at all. Nothing
// observes the latch either way -- NextEntry's closed pre-check runs before
// its r.fatal check, and Reset clears both -- but leaving it out is what lets
// r.fatal be described as archive-level without an exception. Load-bearing in
// one direction: if that pre-check ever moves below the r.fatal check, the
// latch surfaces.
func (r *Reader) latchArchive(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) ||
		errors.Is(err, ErrReaderClosed) {
		return err
	}
	// Nothing latches while this Reader is closed, whatever the error says.
	//
	// NextEntry translates its own scan's error before it gets here, but
	// nextVolumePayload (splice.go) calls this directly from five places, and
	// a Close landing mid-splice makes r.vol.next() return the stream's error
	// -- os.ErrClosed for an *os.File. That is the caller's own doing wearing
	// the archive's clothes, and latching it would put a caller error on
	// r.fatal, which is documented to hold archive-level failures only.
	//
	// Skipping the latch rather than translating here: the member's verdict is
	// already handled by Entry.finish's override, and r.fatal exists to stop a
	// RETRY resuming past an unresolved failure. A closed Reader has no retry
	// -- NextEntry's pre-check returns before reading r.fatal -- and Reset
	// clears the field anyway, so there is nothing for the latch to guard.
	if r.isClosed() {
		return err
	}
	r.fatal = err
	return err
}

// nextEntry is NextEntry's scan loop, unlatched: every error it returns is
// evaluated by NextEntry for whether it should end traversal for the rest of
// this Reader's life. Nothing below this point may be called except through
// NextEntry.
func (r *Reader) nextEntry() (*Entry, error) {
	r.finishActive()
	for {
		var h *blockHeader
		if r.staged != nil {
			// Consumed before the volume is touched: volume.next() would skip
			// this header's payload on the way to the next block. See
			// Reader.staged.
			h, r.staged = r.staged, nil
		} else {
			if r.vol == nil {
				if err := r.openNextVolume(); err != nil {
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
					r.closeCurrentVolume()
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
	if e == nil {
		return
	}
	if r.solid {
		r.entry = nil
		_ = e.Close()
	} else {
		r.severActive()
	}
	if e.short() || (e.done != nil && !errors.Is(e.done, io.EOF) &&
		!errors.Is(e.done, ErrChecksumUnsupported)) {
		r.win.MarkIncomplete()
	}
}

// severActive terminates the member in progress without reading anything.
//
// e.src bottoms out on the volume's aliased v.body, which the next v.next()
// call re-points to describe a following block, and on the splicer, which
// pulls volumes off the channel when it wants a continuation. An abandoned
// Entry holding either would serve a later block's bytes with a nil error
// instead of reporting its own truncation -- and after Reset it would do
// that against a DIFFERENT archive, consuming volumes the new traversal has
// not seen yet. Cutting the source, rather than decoding to completion, is
// also what keeps a non-solid abandon cheap.
func (r *Reader) severActive() {
	e := r.entry
	r.entry = nil
	if e == nil {
		return
	}
	e.src = nil
	if e.done == nil {
		if e.short() {
			_ = e.finish(e.truncated())
		} else {
			_ = e.finish(nil)
		}
	}
}

// dispatch consumes one block and reports what it was.
//
// A nil Entry with a nil error means the block held nothing the caller wants
// and scanning continues. Nothing here discards payload: volume.next() does
// that on the way to the following header, unconditionally, whether or not
// anything below looked at the block.
//
// Only the file case lives here. Every other block type means the same thing
// to this path as it does to the splice, so it is settled by
// handleNonFileBlock rather than restated -- see that function for why that
// is not a stylistic preference.
func (r *Reader) dispatch(h *blockHeader) (*Entry, error) {
	if h.Type != headerTypeFile {
		// Returned unlatched: NextEntry latches every error this scan loop
		// reports. A volume closed by an end header leaves r.vol nil, which
		// nextEntry's loop reads at the top of its next iteration as "open
		// the next one".
		return nil, r.handleNonFileBlock(h)
	}
	// Fetched once for the whole function, and handed to every Entry built
	// below. Only Reset replaces r.done, and Reset is a traversal call that
	// cannot run while this one is in progress, so the value cannot change
	// underneath dispatch -- but re-fetching it per call site took volMu again
	// each time, and did so twice on the one path that builds an Entry and
	// then refuses it. Hoisting also states the invariant where it can be
	// read, rather than leaving it to be re-derived from the mutual
	// exclusivity of six returns.
	done := r.doneChan()
	fh, err := parseFileHeader(h)
	if err != nil {
		// A member whose identity survived the failure is refused by NAME,
		// so the caller learns the archive held something it could not
		// read. One that failed before its name was decoded has nothing to
		// report and is skipped as before. Either way volume.next() drops
		// the block's declared payload on the way to the next header.
		if fh != nil && fh.FirstBlock {
			r.win.MarkIncomplete()
			return terminalEntry(fh, err, done), nil
		}
		// Damage is recorded from what happened to the file, never from
		// what the caller is told about it. A member skipped here is one
		// whose name was never decoded, so nothing can be reported -- but
		// it still contributed no bytes, and a solid successor's
		// back-references assume otherwise. Marking only the named path
		// left exactly the unreportable failures decoding a successor
		// against history nobody wrote.
		if fh == nil {
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
	// Refused before the bomb ratio and before BeginFile: a member whose
	// compression algorithm this library does not implement cannot be
	// reasoned about at all, so nothing downstream should touch the
	// window on its behalf.
	//
	// RAR 7.0 raised this field and changed nothing a traversal can see
	// from outside a file header -- the signature, block framing and vint
	// encoding are identical -- so detectVersion cannot separate them and
	// every member with a nonzero method was handed to the RAR5 decoder.
	// That produced garbage rather than an error, and the CRC32 caught it
	// only after the whole member had been decompressed and delivered.
	//
	// ErrUnsupportedFormat rather than a new sentinel: it already means
	// "an archive this library cannot decode", which is exactly this, and
	// a caller can do nothing different for a RAR7 member than for a RAR3
	// signature. The version is named in the message.
	if fh.UnpackVersion != unpackVersionRAR5 {
		r.win.MarkIncomplete()
		return terminalEntry(fh, fmt.Errorf(
			"%w: file %q declares unpack version %d, this library decodes "+
				"version %d (RAR 5.0)", ErrUnsupportedFormat, fh.Name,
			fh.UnpackVersion, unpackVersionRAR5), done), nil
	}
	// The multiplication is guarded, not replaced by a division: a
	// division floors, so it would let a member declaring exactly one
	// byte past the ratio through, and this guard must not be weakened.
	// A packed size above MaxInt64/1000 cannot reach the ratio at all --
	// no unpacked size fits -- so it is not a bomb, whereas the
	// unguarded product wrapped negative there and refused every member
	// over 1 MB.
	expands := fh.PackedSize == 0 ||
		(fh.PackedSize <= math.MaxInt64/1000 && fh.UnpackedSize > 1000*fh.PackedSize)
	if fh.UnpackedSize > 1024*1024 && expands {
		r.win.MarkIncomplete()
		return terminalEntry(fh, ErrRarBombDetected, done), nil
	}
	if err := r.win.BeginFile(fh.Solid); err != nil {
		r.win.MarkIncomplete()
		return terminalEntry(fh, err, done), nil
	}
	// e is built before the splicer, and the splicer before the decode
	// chain, because the splicer consults e through lastBlock() while
	// reading -- both must exist before the chain's first Read. e.src is
	// filled in only once the chain is known to build successfully.
	e := newEntry(fh, nil, done)
	splicer := &multiVolumePayloadReader{r: r, e: e, src: r.vol.payload()}
	src, err := r.buildChain(fh, splicer)
	if err != nil {
		r.win.MarkIncomplete()
		return terminalEntry(fh, err, done), nil
	}
	e.src = src
	r.entry = e
	return e, nil
}

// handleNonFileBlock applies the archive-wide effect of a block that is not a
// file header, and is the only place those effects are written down.
//
// The two header-reading paths -- Reader.dispatch and nextVolumePayload
// (splice.go) -- differ only in what they do with a FILE block. They used to
// restate the other arms each, and disagreed about them three separate times
// in one change: an archive-header failure latched in one path and not the
// other, HEAD_CRYPT armed in dispatch alone (header-encrypted multi-volume
// archives were unreadable across a boundary), and a corrupt continuation
// header ending the whole archive in one path while costing one member in the
// other. Two of those were data loss. Sharing the arms is what makes a fourth
// disagreement unrepresentable rather than merely unlikely.
//
// Nothing here discards payload: volume.next() does that on the way to the
// following header, unconditionally, whether or not any case below looked at
// the block. That is why no arm needs to report whether it "handled" the
// block -- a case that does nothing is already correct.
//
// A nil r.vol on return means an end header closed this volume and the caller
// must move to the next one. nextEntry's loop already does that at the top of
// every iteration; the splice, which owns its own loop, acts on it explicitly.
//
// Every error returned is archive-level and UNLATCHED, so a call site can
// wrap it in latchArchive in one expression.
func (r *Reader) handleNonFileBlock(h *blockHeader) error {
	switch h.Type {
	case headerTypeArchive:
		ah, err := parseArchiveHeader(h)
		if err != nil {
			// Fatal, not skipped. The archive header occurs once per volume
			// and defines archive-wide semantics, including whether the
			// archive is solid. NextEntry's error set is explicitly
			// archive-level, and a header this library cannot parse is
			// precisely an archive-level problem: continuing past it means
			// proceeding with unknown archive-wide semantics. Wrapped so a
			// caller can alarm on ErrCorruptArchiveHeader specifically while
			// errors.Is still reaches the underlying parse failure -- see
			// ErrCorruptArchiveHeader's doc comment. Both call sites latch
			// this (see Reader.fatal) so a second call cannot resume past it.
			return fmt.Errorf("%w: %w", ErrCorruptArchiveHeader, err)
		}
		r.solid = r.solid || ah.Solid

	case headerTypeEncryption:
		// Every volume of a header-encrypted archive repeats its own
		// HEAD_CRYPT in plaintext, and each volume is a fresh value whose
		// header decryptor starts nil. Skipping this block left the rest of
		// that volume's headers read as plaintext when they are ciphertext,
		// which surfaced as ErrBadHeaderCRC partway through a member.
		return r.armHeaderDecryption(h)

	case headerTypeEnd:
		// The end header is the archive saying this volume holds no further
		// blocks, so nothing after it is part of the archive and this
		// traversal has no business parsing it. Falling through to the
		// default case left the volume open and read whatever followed:
		// trailing padding or sector alignment failed its CRC and ended the
		// archive with ErrBadHeaderCRC after every member had been delivered
		// intact.
		r.closeCurrentVolume()

	default:
		// Everything the caller never sees, including service records --
		// quick open, comment, recovery, ACL, stream. Those reuse the
		// file-header layout, so routing them to the file case would surface
		// one as a member named after the record and hand its bytes over as
		// content.
	}
	return nil
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
	// This early return is also what makes hasCheck below always true:
	// verifyFileHeaderPassword reports hasCheckValue=false only when EncCheck
	// is nil, and that case never reaches the loop.
	if fh.EncCheck == nil {
		return r.passwords[0], nil
	}
	for _, candidate := range r.passwords {
		ok, _, err := verifyFileHeaderPassword(fh, candidate)
		if err != nil {
			// An empty candidate cannot be checked against anything, which
			// is a fact about that candidate and not about the archive. It
			// used to end the scan, so a caller passing "" alongside real
			// guesses -- the natural way to say "try no password first" --
			// never reached the guess that would have worked.
			if errors.Is(err, ErrPasswordRequired) {
				continue
			}
			return "", err
		}
		if ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}

// resolveHeaderPassword is resolvePassword for archive-level header
// encryption, whose check value lives on the cryptHeader rather than on a file
// header.
func (r *Reader) resolveHeaderPassword(ch *cryptHeader) (string, error) {
	if r.hasResolved {
		return r.resolved, nil
	}
	if len(r.passwords) == 0 {
		return "", ErrPasswordRequired
	}
	// No check value at all: the same case resolvePassword handles above,
	// and for the same reason. Every candidate is unverifiable against this
	// header, so scanning them is pointless -- and latching the first as
	// though it were knowledge would suppress the scan for a later header
	// that DOES carry a check value.
	// As above: verifyCryptHeaderPassword reports hasCheckValue=false only
	// for a nil CheckValue, so the loop below never sees it.
	if ch.CheckValue == nil {
		return r.passwords[0], nil
	}
	for _, candidate := range r.passwords {
		ok, _, err := verifyCryptHeaderPassword(ch, candidate)
		if err != nil {
			if errors.Is(err, ErrPasswordRequired) {
				continue
			}
			return "", err
		}
		if ok {
			r.resolved, r.hasResolved = candidate, true
			return r.resolved, nil
		}
	}
	return "", ErrWrongPassword
}

// unpackVersionRAR5 is the only compression algorithm version this library
// implements. The field it is compared against is attacker-supplied like every
// other, but there is nothing to cross-check it against: a RAR7 member is a
// well-formed header for a format we do not decode, not a malformed one.
const unpackVersionRAR5 = 0

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
	win *window
}

func (l *lz50Reader) Read(p []byte) (int, error) {
	return l.dec.Read(l.win, p)
}

type storeReader struct {
	r   io.Reader
	win *window
}

// Read delivers the stored member's bytes from the source and records them as
// window history, so a solid successor can back-reference them.
//
// recordHistory rather than writeBytes: these bytes are not staged for anyone
// to read back -- they went to the caller from s.r -- and writeBytes would
// leave them counted as unread with no drain step to clear them. A stored
// member larger than the window then lapped the read pointer and left full
// and Available describing a buffer that no longer existed.
func (s *storeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.win.recordHistory(p[:n])
	}
	return n, err
}

// chanClosed reports whether ch has been closed, without receiving from it.
//
// The shape is io.Pipe's (src/io/pipe.go, pipe.read): a select with a default
// is how the standard library asks a done channel whether cancellation has
// happened. A nil ch is never ready and so reports false -- which is
// context.Context's documented meaning for a nil Done channel, "this can never
// be cancelled", and is exactly right for an Entry with no Reader behind it.
func chanClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// doneChan returns the done channel in force, under the lock.
//
// Under the lock because Reset REPLACES r.done; this is the only way the field
// is read outside a critical section that already holds volMu, so there is no
// unsynchronised read of it anywhere. Called once per NextEntry and once per
// admitted member -- never per byte, which is the cost profile volMu already
// has.
func (r *Reader) doneChan() <-chan struct{} {
	r.volMu.Lock()
	done := r.done
	r.volMu.Unlock()
	// --- no lock held below this line ---
	return done
}

// isClosed reports whether Close has been called on the archive in force.
func (r *Reader) isClosed() bool { return chanClosed(r.doneChan()) }

// takeVolume removes the open volume from the Reader and returns it together
// with the done channel in force, leaving the caller to close the volume
// outside the lock.
//
// This and publishVolume are the ONLY two functions that assign r.vol -- see
// the vol field for the invariant that buys, and why it is expressed as
// something grep can check rather than as a rule six call sites remember.
// publishVolume exists for that reason rather than for reuse: it has one
// caller, and inlining it would put a third r.vol write back into nextVolume.
//
// done comes back from the same acquisition because nextVolume needs the pair
// and a second accessor for one channel read would be a third place this lock
// is taken. Receive-only, matching doneChan: no caller sends or closes.
func (r *Reader) takeVolume() (*volume, <-chan struct{}) {
	r.volMu.Lock()
	v, done := r.vol, r.done
	r.vol = nil
	r.volMu.Unlock()
	// --- no lock held below this line ---
	return v, done
}

// publishVolume attaches v as the open volume, or reports false if the Reader
// was closed first -- in which case v is closed here and never becomes
// reachable.
//
// The re-check is under the same lock Close takes, so only two orderings are
// possible: either Close saw this volume, or this saw Close. The select in
// nextVolume proves nothing on its own -- when both its cases are ready Go
// picks at random, so a Close that landed during acquisition can have taken
// the volumes branch anyway, and by then Close has already read r.vol, drained
// the queue and returned.
func (r *Reader) publishVolume(v *volume) bool {
	r.volMu.Lock()
	if chanClosed(r.done) {
		r.volMu.Unlock()
		// --- no lock held below this line ---
		_ = v.Close()
		return false
	}
	r.vol = v
	r.volMu.Unlock()
	// --- no lock held below this line ---
	return true
}

// closeCurrentVolume closes the open volume and clears the pointer, for the
// four callers that need no done channel.
//
// All four are spent-volume closes -- once per volume, never per byte, which
// is the cost volMu was always documented to have. Three of them wrote r.vol
// with no lock at all (reader.go twice, splice.go once); the fourth, Reset,
// was already doing exactly this inline.
func (r *Reader) closeCurrentVolume() {
	if v, _ := r.takeVolume(); v != nil {
		_ = v.Close()
	}
}

// Close releases the Reader and unblocks a call waiting for the next volume.
//
// It closes the volume currently open and every volume already queued on the
// channel, and makes every later NextEntry return ErrReaderClosed -- as well
// as any Entry still owed bytes, from both Read and Close. A member that
// already produced everything it declared is NOT cancelled by a Close that
// arrives afterwards; see ErrReaderClosed for the two exceptions and why they
// are deliberate. It is idempotent.
//
// Close is the ONE method safe to call from another goroutine while a read is
// in progress. Every other method requires the caller's own serialisation --
// this type is not concurrently safe and does not become so. The asymmetry is
// the point: a Reader blocked on a volume that will never arrive cannot
// rescue itself, because the only other thing that ends that wait is the
// producer closing the channel, and a stalled producer is exactly when a
// caller needs to give up.
//
// That is also how a context reaches this library without it storing one:
//
//	r := rarengine.NewReader(volumes)
//	defer r.Close()
//	context.AfterFunc(ctx, func() { r.Close() })
//
// which is why NextEntry and Entry.Read take no context. Entry.Read reaches
// the same volume receive through the splice and must satisfy io.Reader, so a
// context parameter could never have covered it -- the long operation would
// have stayed uncancellable while the short one gained a ceremony.
//
// Close does not nil the open volume and does not touch its fields. It reads
// the pointer under volMu and closes the underlying stream; the traversal
// alone writes r.vol, v.rc is immutable after construction, and v.body is
// written only by the traversal.
//
// An earlier version of this comment claimed the volume's body was zeroed so
// an in-flight read "sees EOF rather than a nil dereference", and the same
// commit assigned r.vol = nil three lines below. Both halves were false: the
// assignment was the nil dereference. The zeroing was also below decoder50's
// window, so it did not stop a compressed member anyway.
//
// What Close guarantees an in-flight reader is a VERDICT, not silence. A
// sequential Close-then-read touches the stream not at all: NextEntry and
// Entry.Read both refuse on the done channel before reading. A Close landing
// concurrently, mid-call, does reach the stream -- refusing that would mean a
// lock per read -- and what it gets back is translated rather than reported:
// Entry.finish overrides a short member's verdict and NextEntry translates the
// scan's, so the caller is told ErrReaderClosed and never os.ErrClosed or
// ErrTruncatedFile. This is os.File.wrapErr's arrangement, which turns
// poll.ErrFileClosing into ErrClosed at the same boundary.
//
// One limit remains, and it is the caller's rather than this library's.
// Unblocking a read that is stalled inside the underlying stream depends on
// that stream's own Close being safe to call while a Read is in flight, and so
// does the mid-call case above. os.File and net.Conn are; a type doing its own
// buffering may not be. This is the same division io.Pipe and net.Conn draw,
// and it is why Close closes the stream rather than trying to interrupt a read
// it does not own.
//
// After Close, Reset revives the Reader for a different archive. Close ends
// an archive, not the 32 MB window.
func (r *Reader) Close() error {
	r.volMu.Lock()
	// Idempotent without a sync.Once, deliberately. io.Pipe uses one; a pipe
	// is never reset, and Reset REPLACES this field, so a Once would be copied
	// out from under a Close already inside its Do -- see volMu's comment.
	if !chanClosed(r.done) {
		close(r.done)
	}
	// Read, never written. This assignment was the second writer of the field,
	// and it is what every unlocked traversal read raced against -- and what
	// made dispatch's r.vol.payload() a reachable nil dereference, observed at
	// 9 panics per 400 iterations without the race detector.
	//
	// Dropping it also drops an accidental ownership handoff: with Close
	// clearing the pointer, whichever goroutine read it first won and the
	// other saw nil, so only one of them called v.Close(). volume.closeOnce is
	// what absorbs that now, which is why volume.Close had to stop mutating
	// before this assignment could be removed.
	v := r.vol
	// Snapshotted for the same reason as r.done: Reset replaces this field,
	// so draining r.volumes after the unlock would race with a revival and
	// could drain the NEW archive's channel.
	volumes := r.volumes
	r.volMu.Unlock()
	// --- no lock held below this line ---
	var err error
	if v != nil {
		err = v.Close()
	}
	drainVolumes(volumes)
	return err
}

// drainVolumes closes everything already queued on ch.
//
// Non-blocking on purpose. A channel the producer has not closed has no end
// to wait for, so this takes what is there and stops; anything sent afterwards
// belongs to a producer that has not yet noticed it should stop, and closing
// it is that producer's job. Draining until close would hang exactly in the
// case Close exists to escape.
func drainVolumes(ch <-chan io.ReadCloser) {
	for {
		select {
		case rc, ok := <-ch:
			if !ok {
				return
			}
			if rc != nil {
				_ = rc.Close()
			}
		default:
			return
		}
	}
}

// openNextVolume advances to the next volume, skipping any that cannot be
// opened because they ended inside their signature.
//
// Empty and truncated parts are damage, recorded and reported once the
// volumes run out -- not a reason to stop reading the parts that are still
// intact, which is the same judgement the scan makes about a cut inside a
// block. A bad signature is deliberately NOT skipped: that is a different
// fact, a stream that is not this archive, and it stays fatal.
func (r *Reader) openNextVolume() error {
	for {
		err := r.nextVolume()
		if err == nil {
			return nil
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			r.damaged = err
			continue
		}
		return err
	}
}

// nextVolume closes the current volume and opens the next.
//
// Every failure leaves r.vol nil, which is a lifetime rather than a rule:
// takeVolume clears the field up front and publishVolume is the only thing
// that sets it again, so a failed advance has nothing to leave behind. Under
// the previous design this had to be maintained by hand at each exit, and a
// volume left standing after a failure was read again at whatever offset the
// failure stopped at.
func (r *Reader) nextVolume() error {
	// The previous volume is finished with by the time this runs, so closing
	// it here races with nothing.
	prev, done := r.takeVolume()
	if prev != nil {
		_ = prev.Close()
	}
	var rc io.ReadCloser
	var ok bool
	select {
	case rc, ok = <-r.volumes:
		if !ok {
			return ErrNoNextVolume
		}
	case <-done:
		// Close was called, possibly from another goroutine and possibly
		// while this receive was already blocked. That is the whole reason
		// Close exists.
		return ErrReaderClosed
	}
	if rc == nil {
		// A nil element on the channel is the caller's bug, but the library
		// must report it rather than dereference it: openVolume would read
		// the signature straight out of a nil interface and take the process
		// down with it.
		return errors.New("rarengine: nil volume stream on the volumes channel")
	}
	v, err := openVolume(rc)
	if err != nil {
		_ = rc.Close()
		return err
	}
	if !r.publishVolume(v) {
		return ErrReaderClosed
	}
	return nil
}
