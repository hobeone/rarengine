package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// Entry is one member of the archive.
//
// It owns every piece of state belonging to that member: the reader chain its
// bytes come from, the header in force, how many bytes are still owed, the
// running checksum, and whether it has terminated. That state used to be
// spread across three types and mutated from five places, which is what let a
// member end without anyone deciding whether it had ended successfully.
//
// The verdict lives here rather than being returned by the traversal's Next.
// Those are different facts -- "what is the next member" and "how did the
// previous one end" -- and folding both into one return value is what forced
// the traversal to prove, at every failure site, that the stream was still
// positioned. Attached to the member it describes, the verdict needs no such
// proof.
type Entry struct {
	// Header is the FIRST block's header and does not change for the life of
	// the entry, so a caller keeps the header it was handed.
	//
	// On an entry refused for its header -- an unknown or negative declared
	// size, or a failing or duplicated extra record -- only Name and
	// Encrypted are dependable; UnpackedSize is decoded but not dependable,
	// and every other field is either decoded correctly or, for a field
	// belonging to one of the records that failed to parse, zero or partly
	// filled from that record. Encrypted reports that the member carries an
	// encryption record, not that it is usable.
	Header *FileHeader

	// cur is the header in force, which for a multi-volume member is NOT
	// Header: the whole-file CRC32 and UseMac are recorded in the LAST part's
	// header, and LastBlock is what tells the splice a boundary from an end.
	cur *FileHeader

	src       io.Reader
	size      int64
	remaining int64
	crc       uint32

	// done is the terminal state. Once set, every Read returns it and the
	// entry produces nothing further. It is what makes a failure durable
	// rather than something the next Read can erase.
	done error

	// cancelled is the done channel of the archive this member belongs to,
	// closed by Reader.Close. This is context.Context's Done() shape, and a
	// nil channel carries context's documented meaning: never ready, so this
	// member has no Reader that can cancel it. That is true of terminalEntry's
	// refusals and of the hand-built entries in the tests, so nil needs no
	// guard and is not a footgun.
	//
	// A <-chan struct{} rather than a *Reader: reader.go builds entries and
	// entry.go knows nothing about traversal, so a back-pointer would invert
	// that to read one signal.
	//
	// Captured once at construction and never re-read from the Reader, which
	// is what makes the verdict durable: Reset REPLACES Reader.done, so a
	// member the caller retained across a Close/Reset pair still holds the
	// CLOSED channel of its own archive and cannot be un-cancelled by the next
	// archive starting. A boolean beside the channel could not do that without
	// an ordering rule inside Reset.
	//
	// Checked at THIS layer rather than lower because the chain buffers.
	// decoder50.Read serves from its outbuf and then from the window, touching
	// its source only when Available() hits zero, so a compressed member can
	// hold up to the window's fill target (half the window, capped at 16 MiB)
	// in decoded plaintext below Entry.Read and
	// above everything else. A check under that buffer keeps delivering real
	// content with nil errors until it drains.
	cancelled <-chan struct{}
}

func newEntry(fh *FileHeader, src io.Reader, cancelled <-chan struct{}) *Entry {
	e := &Entry{
		Header:    fh,
		cur:       fh,
		size:      fh.UnpackedSize,
		remaining: fh.UnpackedSize,
		cancelled: cancelled,
	}
	if src != nil {
		e.setSource(src)
	}
	return e
}

// hashedSource is a member's byte source with BLAKE2sp computed over what
// passes through it. It is installed ONLY for a member whose FIRST header
// records a BLAKE2 digest, so a member that records none has no hasher, no
// wrapper and no extra indirection: the CRC32-only path is untouched.
//
// It is a wrapper around the source, not a field of Entry, for a measured
// reason: a pointer field took Entry from 80 bytes to 88, which is past the
// 80-byte allocator size class, and every NextEntry on every archive -- hashed
// or not -- paid +16 B/op (Store 1144 -> 1160, Compress 1824 -> 1856). Here
// only the members that need a hasher pay for one.
//
// Deciding from the first header is right, and that was measured rather than
// assumed (rar 7.12, -m0 and -m3 archives split across 3 to 6 volumes, every
// part parsed with parseFileHeader). Under -htb EVERY part carries a BLAKE2
// record and none carries a CRC32; under the default every part carries a
// CRC32 and none a BLAKE2 record. What differs between parts is what the
// record covers: on a non-final part it is the PACKED bytes of that part
// (unrar lists it as "Pack-BLAKE2"), and only the final part's record is the
// whole-file hash of the plaintext. So the first part names the algorithm even
// though it does not carry the digest that matters, and verifyChecksum
// compares the digest in e.cur, the last part's, at the end.
//
// Not installed for an encrypted member: -htb over encryption records a
// key-derived MAC on the final part (UseMac, which a non-final part does not
// yet show), so a plaintext hash would be computed and never compared. That
// is pure waste on a path -- encrypted multi-volume -htb -- that is not rare.
type hashedSource struct {
	src io.Reader
	h   blake2sp
}

func (s *hashedSource) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	if n > 0 {
		_, _ = s.h.Write(p[:n])
	}
	return n, err
}

// setSource installs the member's byte source, wrapping it in a hasher when
// the first header calls for one. The one place e.src is assigned, so the
// decision cannot be made differently on two paths.
func (e *Entry) setSource(src io.Reader) {
	fh := e.Header
	if fh.HasBlake2sp && !fh.Encrypted && !fh.UseMac {
		hs := &hashedSource{src: src}
		hs.h.init()
		src = hs
	}
	e.src = src
}

// terminalEntry builds a member that is already finished, carrying cause.
//
// Refusals arrive this way -- a rar bomb, a broken solid run, an unparsable
// file header, an unresolvable password -- so that every per-member outcome
// reaches the caller through the Entry and NextEntry's error set stays
// archive-level only, rather than archive-level-with-exceptions.
func terminalEntry(fh *FileHeader, cause error, cancelled <-chan struct{}) *Entry {
	return &Entry{Header: fh, cur: fh, done: cause, cancelled: cancelled}
}

// linkEntry builds the member for a link: a header, and nothing to read.
//
// Header.UnpackedSize stays as the archive declared it -- the header is
// faithful -- but the entry's own byte budget is zero, because the declared
// size of a link is not a content size (a symlink declares its target's
// length, a hard link its target's). Close therefore reaches the same
// zero-length completion a directory or an empty file does: finish(nil),
// where verifyChecksum's e.size == 0 gate finds nothing to compare.
//
// Read does NOT take that completion. It reports ErrLinkEntry at its entrance,
// so a consumer that copies every entry without looking at LinkType fails
// where it would otherwise write an empty file and report success. src stays
// nil because there is nothing to read, and the entrance arm is above the
// ErrNoActiveFile check, which would otherwise describe a link as "no active
// file".
func linkEntry(fh *FileHeader, cancelled <-chan struct{}) *Entry {
	return &Entry{Header: fh, cur: fh, cancelled: cancelled}
}

// advanceVolume replaces the header in force when the member continues into
// the next volume. It is a named transition rather than a bare field write so
// that the one place allowed to swap the header mid-member stays visible.
func (e *Entry) advanceVolume(fh *FileHeader) { e.cur = fh }

// lastBlock reports whether the header in force marks the member's final
// block, which is how the splice tells a real end from a volume boundary.
func (e *Entry) lastBlock() bool { return e.cur.LastBlock }

// short reports that the member stopped before its declared size.
func (e *Entry) short() bool { return e.remaining > 0 }

// Read produces the member's decompressed bytes, and is the only path that
// advances the byte budget or the running checksum.
//
// A link member (Header.LinkType != LinkNone) has no content: Read returns
// ErrLinkEntry, every time until Close, and does not record it as the
// member's verdict, so Close still reports nil. A caller that copies every
// entry without looking at LinkType therefore fails rather than writing an
// empty file; a caller that checks LinkType, creates the link (or declines to)
// and never reads gets a clean Close. After Close, Read reports the recorded
// verdict like it does for every member. Header.UnpackedSize is not a content
// size for a link.
func (e *Entry) Read(p []byte) (int, error) {
	// A terminated member yields no further bytes. io.Reader does not forbid a
	// reader from producing data after reporting a failure, and the decoders
	// below are stateful enough that arguing case by case is not worth
	// depending on. Without this those bytes would be appended to a member the
	// caller was already told had failed.
	if e.done != nil {
		return 0, e.done
	}
	// A link has nothing to read. Above the nil-src check on purpose: a link's
	// src is nil, and ErrNoActiveFile would say something different. cur is
	// nil only on a zero-value Entry, which has no header at all.
	if e.cur != nil && e.cur.LinkType != LinkNone {
		return 0, ErrLinkEntry
	}
	if e.src == nil {
		return 0, ErrNoActiveFile
	}
	// Tested with <= rather than ==. The parsers reject a negative declared
	// size and this is the backstop: reaching the clamp below with a negative
	// remaining panics on the slice bound, turning a crafted header into a
	// process kill. A zero-length member also never enters the read path, so
	// completing it here is what gives it a terminal state at all.
	if e.remaining <= 0 {
		return 0, e.finish(nil)
	}
	// The caller closed the Reader. This is the ENTRANCE guard, and it is the
	// only thing standing between a sequential cancellation and full, clean
	// delivery of the member: without it the read reaches a source that is
	// still serving (a caller's ReadCloser need not fail after Close), the
	// member meets its declared size, and finish reports success with a
	// passing CRC. finish's override does NOT cover this -- there is no error
	// for it to reclassify -- see CLAUDE.md, "Cancellation is one channel,
	// checked above the decode chain".
	//
	// BELOW the remaining <= 0 arm, and that is the whole of why this block is
	// not three lines higher. finish's override is gated on short() precisely
	// so a member that produced every byte it declared is never blamed on a
	// cancellation -- and passing ErrReaderClosed in from HERE routes around
	// that gate, because finish takes it as the incoming err rather than as
	// something to reclassify. Above the arm, a zero-length member -- an empty
	// file, or any directory -- reported "reader is closed" after a Close it
	// had already completed before, reachable through the documented
	// context.AfterFunc pattern plus a deferred Entry.Close. Below it, a
	// member with nothing left to produce completes cleanly and only a member
	// still owed bytes is cancelled, which is the same rule finish applies.
	//
	// After the e.done guard so a verdict already recorded is not overwritten.
	if chanClosed(e.cancelled) {
		return 0, e.finish(ErrReaderClosed)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > e.remaining {
		p = p[:e.remaining]
	}

	n, err := e.src.Read(p)
	if n > 0 {
		e.crc = crc32.Update(e.crc, crc32.IEEETable, p[:n])
	}
	e.remaining -= int64(n)

	switch {
	case err == nil && e.remaining == 0:
		return n, e.finish(nil)
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF) && e.remaining > 0:
		return n, e.finish(e.truncated())
	case errors.Is(err, io.EOF):
		return n, e.finish(nil)
	default:
		return n, e.finish(err)
	}
}

// Close finishes the member and returns its verdict.
//
// It does NOT drain packed bytes: volume.next() skips whatever a block
// declared and no one claimed, which is required on paths where no Entry
// exists at all -- service records, unknown block types, refused headers. One
// mechanism moves the stream.
//
// Close is idempotent. It reports the same verdict Read recorded, except that
// the success verdict -- recorded internally as io.EOF so Read has exactly
// one thing to return -- is reported as nil here, matching io.Closer's
// convention that Close returns nil on success.
//
// The success check is an identity comparison (e.done == io.EOF), not
// errors.Is. finish assigns the bare io.EOF sentinel itself on success, so
// identity is exact; errors.Is would also report success for any future
// verdict that merely WRAPS io.EOF, silently turning that failure into a
// clean Close -- a member reporting done while the caller believes it
// received everything. This makes ErrTruncatedFile not satisfying
// errors.Is(err, io.EOF) load-bearing for a second, independent reason
// beyond the one at its declaration (callers loop Read until io.EOF): if
// truncation ever satisfied that check, Close would report a truncated
// member as successful too.
func (e *Entry) Close() error {
	if e.done == nil {
		if e.src != nil {
			_, _ = io.Copy(io.Discard, e)
		}
		if e.done == nil {
			_ = e.finish(nil)
		}
	}
	if e.done == io.EOF {
		return nil
	}
	return e.done
}

// finish records the terminal state, once, and returns it. Success is recorded
// as io.EOF so that every terminal state is an error value and Read has
// exactly one thing to return.
//
// The first verdict wins and is never overwritten: Read's guard stops bytes
// escaping, this stops a second call downgrading a recorded ErrCRCMismatch to
// io.EOF. The two protect different things.
func (e *Entry) finish(err error) error {
	if e.done != nil {
		return e.done
	}
	// A member that ran SHORT while its archive's Reader was closed ran short
	// because the caller closed it, and says so -- but it says what else it
	// saw, because the caller may still read this verdict after Close and a
	// member's verdict has to stay true about the bytes it delivered.
	//
	// ErrReaderClosed is the matchable identity; the underlying cause rides
	// along as %v text. That distinction is the whole point of the format
	// string. Every error reaching here from Read's default arm is
	// short-eligible, and that set is not only "the stream said you closed
	// it": it includes nextVolumePayload's continuation-identity refusals
	// (ErrCorruptFileHeader -- the interleaved-member attack), ErrNoNextVolume
	// reached mid-member, and decoder failures. An earlier version assigned
	// ErrReaderClosed outright, so a crafted archive read under a context
	// deadline reported "reader is closed" and errors.Is(err,
	// ErrCorruptFileHeader) was false -- a true accusation downgraded to the
	// caller's own cancellation, which is the mirror of the false accusation
	// this library already treats as its worst failure.
	//
	// %v and NOT %w for the cause: wrapping would make
	// errors.Is(err, ErrTruncatedFile) true, and truncation not satisfying
	// that test is load-bearing at its own declaration.
	//
	// ABOVE verifyChecksum, which is what makes "a checksum verdict is never
	// reclassified" structural rather than a property of the call sites. Below
	// it, a verifyChecksum failure became an incoming err this branch could
	// then consume -- reachable through Entry.Close, which calls finish(nil)
	// unconditionally when e.src is nil. Above it, only an error handed IN can
	// be reclassified, and verifyChecksum's verdicts are final by position.
	//
	// err != nil is load-bearing here rather than a backstop: finish(nil) must
	// not become ErrReaderClosed.
	//
	// Not re-wrapped when the incoming error is already ErrReaderClosed:
	// Read's entrance guard passes that in directly, and wrapping it produced
	// "reader is closed: member ended on: rarengine: reader is closed".
	if err != nil && e.short() && chanClosed(e.cancelled) &&
		!errors.Is(err, ErrReaderClosed) {
		err = fmt.Errorf("%w: member ended on: %v", ErrReaderClosed, err)
	}
	if err == nil {
		err = e.verifyChecksum()
	}
	if err == nil {
		err = io.EOF
	}
	e.done = err
	return e.done
}

// verifyChecksum compares the running CRC32 against the header in force at
// completion, which for a multi-volume member is the LAST part's -- that is
// where the whole-file CRC32 is recorded.
func (e *Entry) verifyChecksum() error {
	// A member that did not produce what it declared has nothing to verify,
	// and verifying it anyway produced a false message: the LastBlock arm
	// below says the member "produced its declared N bytes" -- true only when
	// this guard's condition is false, and every arm after it assumes the
	// same. Reached through Entry.Close, which calls finish(nil)
	// unconditionally when e.src is nil, so the assumption was call-site
	// discipline rather than structure.
	if e.short() {
		return e.truncated()
	}
	// A member cannot honestly complete while a header saying it continues is
	// still in force. Reaching the declared UnpackedSize means every byte has
	// been produced; LastBlock false means the archive says more parts follow.
	// Both cannot be true of a well-formed archive, and the disagreement is
	// what makes the digest below uncomparable: the CRC32 field of a
	// non-final part covers that part's packed bytes, not the file's
	// plaintext, so comparing it reported ErrCRCMismatch on content that had
	// decoded perfectly -- the false accusation this library treats as worse
	// than a missed check.
	//
	// Refused rather than skipped. Returning nil would let a malformed entry
	// complete silently, which is what the checksum machinery exists to
	// prevent; ErrChecksumUnsupported would be a lie of a different kind,
	// telling a caller whose policy is "accept unverifiable" that this is an
	// archive class we cannot check, when it is an archive that contradicts
	// itself. ErrCorruptFileHeader says what is actually wrong, and matches
	// what a continuation whose identity does not match the member gets.
	if !e.cur.LastBlock {
		return fmt.Errorf("%w: file %q: produced its declared %d bytes while a "+
			"header marking a further part was in force",
			ErrCorruptFileHeader, e.Header.Name, e.size)
	}
	// Gated on the produced size, which this type enforces, rather than on
	// IsDir, which the archive asserts and nothing cross-checks. An entry that
	// produced bytes is verified whatever it calls itself; one that produced
	// none has nothing to verify.
	//
	// This precedes every uncheckable-digest arm below, and must: a zero-byte
	// member is not a member whose digest we failed to check, it is a member
	// with nothing to check. While UseMac was tested first, an empty file or a
	// directory inside an encrypted archive reported ErrChecksumUnsupported
	// having produced no bytes at all.
	if e.size == 0 {
		return nil
	}
	// The member produced bytes. Whether anything can be compared against them
	// is decided in one place, so the ordering above cannot drift apart from it.
	// Three archive classes cannot be compared, and they are one verdict:
	//
	//   - UseMac: the digest field holds a key-derived MAC rather than a hash
	//     of the plaintext. The gate is UseMac and not Encrypted -- encryption
	//     alone does not make a digest uncheckable, and RAR says which it is by
	//     setting this flag; gating on Encrypted would hand the archive a bit
	//     that switches verification off. It is read from e.cur because RAR
	//     records it on the header carrying the digest, which for a
	//     multi-volume member is the LAST part's. Reading it at admission saw
	//     the first part's cleared copy and compared a plaintext CRC32 against
	//     a MAC -- a guaranteed false mismatch on every encrypted multi-volume
	//     file.
	//   - A BLAKE2sp digest recorded by the header in force that this entry
	//     never computed: no hasher was started because the FIRST header
	//     recorded none, or the member is encrypted. Unreachable from any
	//     archive rar writes (see hashedSource), and refused rather than passed
	//     because a header that disagrees with itself must not be able to
	//     choose "nothing to check".
	//   - A header recording no digest at all.
	//
	// Which one is a distinction for the message, not for the verdict: a
	// caller can only accept unverifiable content or reject it.
	hs, hashed := e.src.(*hashedSource)
	if e.cur.UseMac || (e.cur.HasBlake2sp && !hashed) ||
		(!e.cur.HasCRC32 && !e.cur.HasBlake2sp) {
		return fmt.Errorf("%w: file %q: %s", ErrChecksumUnsupported,
			e.Header.Name, uncheckableDigest(e.cur))
	}
	// Every digest the header in force records is compared, and every one
	// must match: a header carrying both is not allowed to have one of them
	// ignored, because an archive that could pick which check runs could
	// pick none that fails. The CRC32 is compared first only because it is
	// cheaper; BLAKE2sp's digest is not computed until it is needed.
	if e.cur.HasCRC32 && e.crc != e.cur.CRC32 {
		return fmt.Errorf("%w: file %q: CRC32 computed=%08x header=%08x",
			ErrCRCMismatch, e.Header.Name, e.crc, e.cur.CRC32)
	}
	if e.cur.HasBlake2sp {
		if got := hs.h.sum(); !bytes.Equal(got[:], e.cur.Blake2sp) {
			return fmt.Errorf("%w: file %q: BLAKE2sp computed=%x header=%x",
				ErrCRCMismatch, e.Header.Name, got[:], e.cur.Blake2sp)
		}
	}
	return nil
}

// truncated and the messages in verifyChecksum name the member by
// e.Header.Name, never by the header in force. The digest and its flags must
// come from e.cur -- RAR records them on the LAST part -- but the NAME is the
// member's identity, fixed when it was announced, and a caller matching an
// error against the entry it was handed should not have to know that a later
// volume's header could have carried a different one.
func (e *Entry) truncated() error {
	return fmt.Errorf("%w: file %q: got %d of %d bytes",
		ErrTruncatedFile, e.Header.Name, e.size-e.remaining, e.size)
}

// uncheckableDigest describes why nothing could be compared, for the error
// message only. The verdict does not depend on it -- all of these mean the
// same thing to a caller.
//
// A BLAKE2sp-only header is NOT among the reasons any more: this library
// computes BLAKE2sp, so that class is verified. The BLAKE2sp arm below is the
// residue where a digest is recorded but was never computed.
//
// UseMac is composed with the digest kind rather than short-circuiting it.
// The flag says the recorded value is a key-derived MAC; it does not say WHICH
// field holds it, and rar -ma5 -htb -p sets UseMac with HasCRC32 false and
// HasBlake2sp true. Reporting "not a CRC32 of the plaintext" there named a
// field the header does not carry, and testing HasCRC32 first would have
// dropped the MAC instead. Both facts are true of that archive, so the message
// carries both.
func uncheckableDigest(fh *FileHeader) string {
	switch {
	case fh.UseMac && fh.HasCRC32:
		return "records a key-derived MAC in place of a CRC32 of the plaintext"
	case fh.UseMac && fh.HasBlake2sp:
		return "records a key-derived MAC over a BLAKE2sp digest"
	case fh.UseMac:
		return "records a key-derived MAC"
	case fh.HasBlake2sp:
		// Reached only when no hasher ran, so this is not "cannot compute":
		// the digest is computable and this member was simply never hashed.
		return "records a BLAKE2sp digest that was not computed for this " +
			"member (its first header recorded none, or it is encrypted)"
	default:
		return "records no checksum"
	}
}
