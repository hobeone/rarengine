package rarengine

import (
	"errors"
	"io"
	"iter"
)

// errListedOnly is the verdict of each Entry the listing arm of dispatch
// builds: its header was reported and its content was never admitted for
// reading. A member refused before that arm keeps its refusal as its verdict.
var errListedOnly = errors.New("rarengine: member listed, not extracted")

// ListVolume yields the header of each member that begins in one volume, read
// from r, which may sit at any position in its set. A continuation of a member
// begun in an earlier volume is not reported, and ErrNotFirstVolume never is:
// answering "what starts in this volume" for a later volume is the point.
//
// It reads RAR5 and RAR 1.5-4.x. Each payload is read to skip it, nothing is
// decoded or verified, and no dictionary window is reserved. A RAR 1.5-4.x
// symlink is listed as an ordinary member, LinkType unset: its target is its
// payload, which is not read.
//
// A member refused after its name was decoded -- a header that contradicts
// itself, an unsupported encryption version -- is yielded with a non-nil
// header AND its refusal, and the listing goes on. Only its Name is
// sanitized; the field it was refused for holds what the archive declared.
// A member whose header fails before its name is skipped.
//
// An archive-level error ends the listing, yielded once with a nil header: a
// header-encrypted volume (ListVolume takes no password), an unsupported
// format, a corrupt block or archive header, a volume that ends inside a
// block. Breaking out of the loop ends it early. The caller keeps ownership
// of r; it is not closed.
func ListVolume(r io.Reader) iter.Seq2[*FileHeader, error] {
	return func(yield func(*FileHeader, error) bool) {
		volumes := make(chan io.ReadCloser, 1)
		volumes <- io.NopCloser(r)
		close(volumes)
		rd := NewReader(volumes)
		rd.listing = true
		defer func() { _ = rd.Close() }()
		for {
			e, err := rd.NextEntry()
			// A listing never splices, and NextEntry reports running out of
			// volumes with no member in progress as io.EOF.
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				yield(nil, err)
				return
			}
			// Every Entry a listing returns is terminal, so Close only reports
			// its verdict: errListedOnly from the listing arm, or the
			// refusal of a member dispatch refused before reaching it.
			var refusal error
			if verdict := e.Close(); !errors.Is(verdict, errListedOnly) {
				refusal = verdict
			}
			if !yield(e.Header, refusal) {
				return
			}
		}
	}
}
