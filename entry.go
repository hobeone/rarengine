package rarengine

import (
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
}

func newEntry(fh *FileHeader, src io.Reader) *Entry {
	return &Entry{
		Header:    fh,
		cur:       fh,
		src:       src,
		size:      fh.UnpackedSize,
		remaining: fh.UnpackedSize,
	}
}

// terminalEntry builds a member that is already finished, carrying cause.
//
// Refusals arrive this way -- a rar bomb, a broken solid run, an unparsable
// file header, an unresolvable password -- so that every per-member outcome
// reaches the caller through the Entry and NextEntry's error set stays
// archive-level only, rather than archive-level-with-exceptions.
func terminalEntry(fh *FileHeader, cause error) *Entry {
	return &Entry{Header: fh, cur: fh, done: cause}
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
func (e *Entry) Read(p []byte) (int, error) {
	// A terminated member yields no further bytes. io.Reader does not forbid a
	// reader from producing data after reporting a failure, and the decoders
	// below are stateful enough that arguing case by case is not worth
	// depending on. Without this those bytes would be appended to a member the
	// caller was already told had failed.
	if e.done != nil {
		return 0, e.done
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
	// UseMac is read from the header that records the digest, which RAR sets
	// only on the last part. Reading it at admission saw the first part's
	// cleared copy and then compared a plaintext CRC32 against a key-derived
	// MAC -- a guaranteed false mismatch on every encrypted multi-volume file.
	//
	// The gate is UseMac and not Encrypted: encryption alone does not make a
	// digest uncheckable, and RAR says so by setting this flag. Gating on
	// Encrypted would hand the archive a bit that switches verification off.
	if e.cur.UseMac {
		return fmt.Errorf("%w: file %q", ErrChecksumUnsupported, e.Header.Name)
	}
	// Gated on the produced size, which this type enforces, rather than on
	// IsDir, which the archive asserts and nothing cross-checks. An entry that
	// produced bytes is verified whatever it calls itself; one that produced
	// none has nothing to verify.
	if e.size == 0 || !e.cur.HasCRC32 {
		return nil
	}
	if e.crc != e.cur.CRC32 {
		return fmt.Errorf("%w: file %q: computed=%08x header=%08x",
			ErrCRCMismatch, e.Header.Name, e.crc, e.cur.CRC32)
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
