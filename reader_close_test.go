package rarengine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// TestCloseUnblocksAReaderWaitingForAVolume is the reason Close exists.
//
// The volume receive is otherwise unbounded: the only other thing that ends
// it is the producer closing the channel, and a stalled producer -- a
// download that has hung -- is exactly when a caller needs to give up. A
// Reader in that state could not be abandoned at all.
//
// Mutation check: remove the <-r.done case from nextVolume's select and this
// times out.
func TestCloseUnblocksAReaderWaitingForAVolume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Constructed INSIDE the bubble. synctest only counts a block as
		// durable when the channel was created in the bubble too, so a
		// Reader made outside leaves the goroutine blocked non-durably and
		// Wait never returns.
		//
		// A channel nobody will ever send on or close: the stalled producer.
		r := NewReader(make(chan io.ReadCloser))

		result := make(chan error, 1)
		go func() {
			_, err := r.NextEntry()
			result <- err
		}()

		// Waits until that goroutine is DURABLY blocked, which is the state
		// under test. A sleep only guesses at it: too short and this tests
		// the already-closed path instead, too long and it is dead time in
		// every run.
		synctest.Wait()
		_ = r.Close()

		// No timeout arm. Inside a bubble, a Close that fails to release is
		// a deadlock synctest reports as one -- a better failure than a
		// wall-clock timeout, and it cannot pass by accident on a slow
		// machine.
		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("NextEntry = %v, want ErrReaderClosed", err)
		}
	})
}

// Close must also release a member spanning volumes, because Entry.Read
// reaches the same receive through the splice. This is the case a context
// parameter on NextEntry could never have covered: Entry.Read satisfies
// io.Reader and cannot take one.
func TestCloseUnblocksAMemberWaitingForItsContinuation(t *testing.T) {
	// One volume holding a member that says it continues, and a channel that
	// never delivers the next part.
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa", unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	synctest.Test(t, func(t *testing.T) {
		// Inside the bubble, as above.
		volumes := make(chan io.ReadCloser, 1)
		volumes <- &mockReadCloser{bytes.NewReader(v1)}
		// deliberately not closed: the second part never arrives

		r := NewReader(volumes)
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}

		result := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(e)
			result <- err
		}()

		synctest.Wait()
		_ = r.Close()

		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("Entry.Read = %v, want ErrReaderClosed -- Close must "+
				"release a member blocked waiting for its continuation "+
				"volume, the path a ctx on NextEntry cannot reach", err)
		}
	})
}

// Close releases the volumes the caller handed over and will never get back.
// Nothing else closes them: they are queued on a channel the Reader owns the
// receiving end of.
func TestCloseClosesOpenAndQueuedVolumes(t *testing.T) {
	open := &trackedCloser{Reader: bytes.NewReader(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "aaaa", withCRC: true})))}
	queued := []*trackedCloser{
		{Reader: bytes.NewReader(nil)},
		{Reader: bytes.NewReader(nil)},
	}

	volumes := make(chan io.ReadCloser, 3)
	volumes <- open
	for _, q := range queued {
		volumes <- q
	}

	r := NewReader(volumes)
	if _, err := r.NextEntry(); err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if !open.closed {
		t.Error("the open volume was not closed")
	}
	for i, q := range queued {
		if !q.closed {
			t.Errorf("queued volume %d was not closed; nothing else ever "+
				"closes it", i)
		}
	}
}

// Reset closes what the abandoned archive left queued, for the same reason.
func TestResetClosesTheAbandonedChannelsVolumes(t *testing.T) {
	stranded := &trackedCloser{Reader: bytes.NewReader(nil)}
	old := make(chan io.ReadCloser, 1)
	old <- stranded

	r := NewReader(old)
	r.Reset(volumesOf(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "b.bin", content: "bbbb", withCRC: true}))))

	if !stranded.closed {
		t.Error("Reset left a volume queued on the abandoned channel unclosed")
	}
	// The new archive still reads.
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after Reset: %v", err)
	}
	if e.Header.Name != "b.bin" {
		t.Fatalf("entry = %q, want b.bin", e.Header.Name)
	}
}

// Close is idempotent, and every call after it reports the same thing rather
// than describing the caller's own decision as a damaged archive.
func TestCloseIsIdempotentAndLatches(t *testing.T) {
	r := NewReader(volumesOf(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "aaaa", withCRC: true}))))
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for i := range 3 {
		if _, err := r.NextEntry(); !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("NextEntry %d after Close = %v, want ErrReaderClosed", i, err)
		}
	}
}

// Reset revives a closed Reader. Close ends an archive, not the 32 MB window:
// refusing to revive would mean allocating a new one to recover from a
// cancelled download, which is what Reset exists to avoid.
func TestResetRevivesAClosedReader(t *testing.T) {
	r := NewReader(make(chan io.ReadCloser))
	_ = r.Close()
	if _, err := r.NextEntry(); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("NextEntry after Close = %v, want ErrReaderClosed", err)
	}

	const content = "revived"
	r.Reset(volumesOf(rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "c.bin", content: content, withCRC: true}))))

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry after Reset: %v", err)
	}
	got, err := io.ReadAll(e)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != content {
		t.Fatalf("content = %q, want %q", got, content)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Entry.Close: %v", err)
	}
}

// The documented way a context reaches this library. Close is what makes
// NextEntry and Entry.Read need no context parameter of their own.
func TestContextCancellationViaAfterFunc(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := NewReader(make(chan io.ReadCloser)) // stalled producer
		ctx, cancel := context.WithCancel(context.Background())
		stop := context.AfterFunc(ctx, func() { _ = r.Close() })
		defer stop()

		result := make(chan error, 1)
		go func() {
			_, err := r.NextEntry()
			result <- err
		}()

		synctest.Wait()
		cancel()

		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("NextEntry = %v, want ErrReaderClosed -- context "+
				"cancellation did not reach the Reader", err)
		}
	})
}

type trackedCloser struct {
	io.Reader
	closed bool
}

func (t *trackedCloser) Close() error { t.closed = true; return nil }

// TestCloseDuringVolumeAcquisitionDoesNotStrandTheVolume covers the window
// between the volume receive and the assignment that publishes it.
//
// nextVolume selects on the volumes channel and on done. When BOTH are ready
// Go picks at random, so a Close that lands during acquisition can take the
// volumes branch anyway. Close then reads r.vol -- nil, because nextVolume
// clears it before receiving -- drains the queue and returns, and nextVolume
// afterwards publishes a freshly opened volume onto a Reader that is already
// closed. Nothing ever closes it, and traversal carries on reading from it.
//
// Driven at nextVolume rather than through NextEntry because NextEntry's
// own guard short-circuits the already-closed case and would hide this.
// Repeated because the branch is chosen at random: one iteration proves
// nothing either way.
//
// Mutation check: remove the second done check in nextVolume and this fails
// within a few iterations with a volume left open.
func TestCloseDuringVolumeAcquisitionDoesNotStrandTheVolume(t *testing.T) {
	for i := range 200 {
		archive := rar5Archive(t, false, rar5Member(t,
			memberSpec{name: "a.bin", content: "aaaa", withCRC: true}))
		vol := &trackedCloser{Reader: bytes.NewReader(archive)}

		volumes := make(chan io.ReadCloser, 1)
		r := NewReader(volumes)

		// The volume arrives AFTER Close has drained, which drainVolumes
		// documents as possible: a producer that has not yet noticed it
		// should stop keeps sending. Now both select cases are ready at
		// once -- a queued volume and a closed done -- so the branch taken
		// is the runtime's choice.
		_ = r.Close()
		volumes <- vol
		err := r.openNextVolume()

		if !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("iteration %d: openNextVolume = %v, want ErrReaderClosed "+
				"on a closed Reader", i, err)
		}
		if r.vol != nil {
			t.Fatalf("iteration %d: a closed Reader published a volume", i)
		}
		// Whichever branch the runtime took, the volume must not be stranded:
		// either it was never received and is still the producer's, or it was
		// received and this closed it. What must never happen is received,
		// opened, and abandoned.
		queued := len(volumes) == 1
		if !vol.closed && !queued {
			t.Fatalf("iteration %d: a volume was received after Close and "+
				"left open; nothing will ever close it", i)
		}
	}
}

// TestResetIsSafeAgainstAConcurrentClose pins the contract Close's own doc
// creates. Close is callable from another goroutine at any time, and Reset is
// documented as reviving a closed Reader -- so the two run concurrently in the
// pattern this library recommends:
//
//	context.AfterFunc(ctx, func() { r.Close() })
//	...
//	r.Reset(next)     // cancellation may fire at any point, including here
//
// The caller cannot avoid it. context.AfterFunc's stop "does not wait for f to
// complete before returning", so there is no way to establish that no Close is
// in flight. Documenting the hazard instead of fixing it would be documenting
// something a caller cannot act on.
//
// Mutation check: replace the chanClosed(r.done) test under volMu with an
// unsynchronised
// sync.Once and this panics with "close of closed channel", or trips the race
// detector on r.done and r.vol.
func TestResetIsSafeAgainstAConcurrentClose(t *testing.T) {
	for range 300 {
		archive := rar5Archive(t, false, rar5Member(t,
			memberSpec{name: "a.bin", content: "aaaa", withCRC: true}))
		r := NewReader(volumesOf(archive))
		if _, err := r.NextEntry(); err != nil {
			t.Fatalf("NextEntry: %v", err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = r.Close()
		}()
		go func() {
			defer wg.Done()
			<-start
			r.Reset(volumesOf(archive))
		}()
		close(start)
		wg.Wait()
	}
}

// Two Closes racing each other must also not double-close the channel.
func TestConcurrentClosesAreSafe(t *testing.T) {
	for range 300 {
		r := NewReader(volumesOf(rar5Archive(t, false, rar5Member(t,
			memberSpec{name: "a.bin", content: "aaaa", withCRC: true}))))
		if _, err := r.NextEntry(); err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				<-start
				_ = r.Close()
			})
		}
		close(start)
		wg.Wait()
	}
}

// Close concurrent with an active traversal must be race-free and must not
// panic. This is the contract Reader.Close's doc comment states outright.
//
// The `started` channel is load-bearing, not decoration. Without it this test
// passed 6 runs out of 6 at -count=1: Close reaches NextEntry's own closed
// check before the traversal goroutine is scheduled past it, so NextEntry
// returns early and never touches r.vol at all, and the race the test exists
// to catch is never armed. Handing off after the first NextEntry has returned
// puts Close inside the scan rather than in front of it, which reproduced the
// race on 3 runs out of 3.
//
// Still loops: the window between nextEntry's nil check on r.vol and
// dispatch's r.vol.payload() is narrow even once the handoff lands. Without
// -race this same shape produced nil-pointer panics at roughly 9 per 400
// iterations.
func TestCloseDuringTraversalIsRaceFree(t *testing.T) {
	members := make([][]byte, 0, 8)
	for i := range 8 {
		members = append(members, rar5Member(t, memberSpec{
			name:    fmt.Sprintf("m%d.bin", i),
			content: strings.Repeat("payload bytes ", 64),
			withCRC: true,
		}))
	}
	stream := rar5Archive(t, false, members...)

	// Now that ErrReaderClosed is what a cancelled traversal reports, this
	// test asserts the verdict as well as race-freedom. The fixture changes
	// with it: volumesOf's mockReadCloser keeps serving after Close, so no
	// read ever fails and NextEntry's translation has nothing to translate.
	acceptable := func(err error) bool {
		return errors.Is(err, ErrReaderClosed) || errors.Is(err, io.EOF) ||
			errors.Is(err, ErrNoNextVolume)
	}

	for range 200 {
		vol := &closedStreamVolume{r: bytes.NewReader(stream)}
		volumes := make(chan io.ReadCloser, 1)
		volumes <- vol
		close(volumes)
		r := NewReader(volumes)

		started := make(chan struct{})
		var bad error
		var wg sync.WaitGroup
		wg.Go(func() {
			first := true
			for {
				e, err := r.NextEntry()
				if first {
					close(started)
					first = false
				}
				if err != nil {
					if !acceptable(err) && bad == nil {
						bad = fmt.Errorf("NextEntry: %w", err)
					}
					return
				}
				if _, rerr := io.Copy(io.Discard, e); rerr != nil &&
					!acceptable(rerr) && bad == nil {
					bad = fmt.Errorf("Entry.Read %q: %w", e.Header.Name, rerr)
				}
				if cerr := e.Close(); cerr != nil && !acceptable(cerr) &&
					bad == nil {
					bad = fmt.Errorf("Entry.Close %q: %w", e.Header.Name, cerr)
				}
			}
		})

		<-started
		_ = r.Close()
		wg.Wait()

		if bad != nil {
			t.Fatalf("a cancelled traversal reported a cause that is not the "+
				"caller's own Close: %v", bad)
		}
	}
}

// Close must cancel an Entry that is already in flight, and must say that it
// was cancelled.
//
// A single-volume archive on purpose. Every other Close test uses a member
// waiting for a continuation, which is blocked in the volume receive and
// therefore released by the done channel. Nothing covered the case where the
// bytes are simply THERE and Close has to stop them being delivered -- which
// is why a candidate fix that removed volume.Close's body-zeroing without a
// replacement passed the whole suite while turning cancellation into a full,
// CRC-clean delivery of the member.
//
// mockReadCloser's Close does nothing, which is the point: a caller's
// io.ReadCloser is not required to make an in-flight Read fail, so the refusal
// has to come from this library. This is also what makes the test a precise
// pin on Entry.Read's ENTRANCE guard: with that guard deleted, the member
// completes with a nil error and a passing CRC.
//
// ErrReaderClosed rather than ErrTruncatedFile, which is what HEAD reports:
// "the archive ended before the file's declared size was produced" names the
// archive as the cause of something the caller did.
func TestCloseCancelsAnInFlightEntry(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "a.bin", content: "HELLOHELLOHELLOHELLO", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	got, readErr := io.ReadAll(e)
	if len(got) != 0 {
		t.Fatalf("ReadAll after Close returned %d bytes (%q); a cancelled "+
			"read must not deliver the member's content", len(got), got)
	}
	if !errors.Is(readErr, ErrReaderClosed) {
		t.Fatalf("ReadAll after Close = %v, want ErrReaderClosed", readErr)
	}
	if closeErr := e.Close(); !errors.Is(closeErr, ErrReaderClosed) {
		t.Fatalf("Entry.Close after Reader.Close = %v, want ErrReaderClosed; "+
			"the verdict must be durable", closeErr)
	}

	// The verdict carries its cause when there is one, and does not restate
	// itself when there is not. Entry.Read's entrance guard hands finish an
	// ErrReaderClosed directly, and wrapping that produced "reader is closed:
	// member ended on: rarengine: reader is closed".
	if n := strings.Count(readErr.Error(), "reader is closed"); n != 1 {
		t.Fatalf("verdict names itself %d times, want 1: %v", n, readErr)
	}
}

// A member with nothing left to produce completes cleanly, even after Close.
//
// Entry.Read's guard sits below the remaining <= 0 arm for this reason: a
// zero-length member -- an empty file, or any directory -- has already
// produced everything it declared, so a later Close cancels nothing. Reporting
// ErrReaderClosed there would be the same false accusation finish's short()
// gate exists to prevent, arriving by the one path that bypasses it.
func TestZeroLengthMemberIsNotCancelledByALaterClose(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "empty.bin", content: "", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	if verdict := e.Close(); verdict != nil {
		t.Fatalf("zero-length Entry.Close after Reader.Close = %v, want nil; "+
			"a member that produced everything it declared was not cancelled",
			verdict)
	}
}

// closedStreamVolume fails reads after its own Close, the way *os.File does --
// which is what both of this library's consumers actually feed it
// -- an *os.File in both cases. recordingVolume and mockReadCloser keep serving
// after Close, which is the right fixture for proving the refusal comes from
// this library; this is the right fixture for proving that a refusal coming
// from the STREAM is translated rather than reported.
type closedStreamVolume struct {
	r      *bytes.Reader
	closed atomic.Bool
}

func (v *closedStreamVolume) Read(p []byte) (int, error) {
	if v.closed.Load() {
		return 0, os.ErrClosed
	}
	return v.r.Read(p)
}

func (v *closedStreamVolume) Close() error {
	v.closed.Store(true)
	return nil
}

// A sequential Close-then-read must not touch the volume at all.
//
// This pins the ENTRANCE guards -- NextEntry's pre-check and Entry.Read's --
// and nothing more. It deliberately does NOT claim that a closed Reader never
// reads; a Close landing concurrently does reach the stream, and preventing
// that would need a lock per read.
func TestClosedReaderReadsNothingFromItsVolume(t *testing.T) {
	stream := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "AAAA", withCRC: true}),
		rar5Member(t, memberSpec{name: "b.bin", content: "BBBB", withCRC: true}),
	)

	vol := &recordingVolume{r: bytes.NewReader(stream)}
	volumes := make(chan io.ReadCloser, 1)
	volumes <- vol
	close(volumes)

	r := NewReader(volumes)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	// Asserted, not assumed, matching TestPackedRemainder_NoReadAfterVolumeClose:
	// if Reader.Close ever stops closing the open volume, "no reads after
	// close" holds trivially and this test stops exercising its own subject.
	if !vol.closed {
		t.Fatal("Reader.Close did not close the open volume")
	}

	if _, err := io.ReadAll(e); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("ReadAll after Close = %v, want ErrReaderClosed", err)
	}
	if _, err := r.NextEntry(); !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("NextEntry after Close = %v, want ErrReaderClosed", err)
	}
	if vol.readsAfterClose != 0 {
		t.Fatalf("a sequential Close-then-read hit the volume %d times; want 0",
			vol.readsAfterClose)
	}
}

// An Entry retained across Close+Reset keeps reporting the cancellation.
//
// This is the ONLY deterministically reachable path on which Entry.finish's
// override changes a verdict. Reset calls severActive, which stamps
// truncated() on an entry that never reached its declared size -- Entry.Read's
// entrance guard never sees it, because severActive reads nothing -- so
// without the override the caller is told "archive ended before the file's
// declared size was produced" for its own cancellation.
//
// It stays correct with no ordering rule inside Reset, which is what the done
// channel buys over a boolean: the Entry captured the channel of ITS archive,
// and Reset replaces the field rather than reopening the channel, so the
// entry's copy stays closed however Reset's statements are ordered.
//
// Documented pattern, not a contrivance: context.AfterFunc(ctx, r.Close)
// followed by Reset for the next archive is what Reader.Close's own doc
// comment describes, and a deferred Entry.Close is enough to reach it.
func TestRetainedEntrySurvivesCloseThenReset(t *testing.T) {
	stream := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "a.bin", content: "HELLOHELLOHELLOHELLO", withCRC: true,
	}))

	r := NewReader(volumesOf(stream))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry: %v", err)
	}
	if cerr := r.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}
	r.Reset(volumesOf(stream))

	if verdict := e.Close(); !errors.Is(verdict, ErrReaderClosed) {
		t.Fatalf("retained Entry.Close after Close+Reset = %v, want "+
			"ErrReaderClosed", verdict)
	}
}

// BenchmarkNextEntryAfterClose measures the path a cancelled caller actually
// spends its time on, which none of the decode benchmarks reach.
//
// The cancellation verdict formats its cause into the error, and that formatting
// allocates -- inside NextEntry, which CLAUDE.md's no-allocation rule names by
// function. This is the benchmark that rule asks for, and it measures the part
// that repeats: the wrap happens at most ONCE per archive, on the single call
// where a Close lands mid-scan, because every call after it returns through the
// pre-check instead. That steady state is what a cancelled consumer loops on,
// and it must not allocate.
//
// Expect 0 allocs/op. A non-zero result means the pre-check stopped short-
// circuiting and the wrap moved onto the repeated path.
func BenchmarkNextEntryAfterClose(b *testing.B) {
	stream := rar5Archive(b, false, rar5Member(b, memberSpec{
		name: "a.bin", content: "AAAA", withCRC: true,
	}))
	r := NewReader(volumesOf(stream))
	if _, err := r.NextEntry(); err != nil {
		b.Fatalf("NextEntry: %v", err)
	}
	if err := r.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := r.NextEntry(); !errors.Is(err, ErrReaderClosed) {
			b.Fatalf("NextEntry after Close = %v, want ErrReaderClosed", err)
		}
	}
}

// closeOnScanVolume closes the Reader from inside a Read, once armed, and then
// reports what a closed *os.File reports.
//
// This is the only way to reach NextEntry's exit translation deterministically.
// The pre-check has already passed by the time the traversal touches the
// stream, so nothing sequential gets past it -- only a Close landing DURING
// the scan does, which a concurrent test achieves by luck and this achieves by
// construction. Single-goroutine, so the plain bool needs no synchronisation.
type closeOnScanVolume struct {
	r     *Reader
	src   *bytes.Reader
	armed bool
}

func (v *closeOnScanVolume) Read(p []byte) (int, error) {
	if v.armed {
		_ = v.r.Close()
		return 0, os.ErrClosed
	}
	return v.src.Read(p)
}

func (v *closeOnScanVolume) Close() error { return nil }

// A Close landing mid-scan is reported as the caller's own, not the stream's.
//
// This pins NextEntry's exit translation, and it is the only test that does so
// without depending on the scheduler. TestCloseDuringTraversalIsRaceFree
// reaches the same code, but only when a concurrent Close happens to land in
// the window -- it went green on a plain `go test` run with the translation
// deleted, and only failed under -race. A mechanism whose pin fires on some
// runs is a mechanism a later refactor deletes on a green local run.
//
// os.ErrClosed rather than a made-up error: it is what an *os.File returns
// after Close, and both of this library's known consumers
// feed exactly that.
func TestCloseDuringScanIsReportedAsCancellation(t *testing.T) {
	stream := rar5Archive(t, false,
		rar5Member(t, memberSpec{name: "a.bin", content: "AAAA", withCRC: true}),
		rar5Member(t, memberSpec{name: "b.bin", content: "BBBB", withCRC: true}),
	)

	vol := &closeOnScanVolume{src: bytes.NewReader(stream)}
	volumes := make(chan io.ReadCloser, 1)
	volumes <- vol
	close(volumes)

	r := NewReader(volumes)
	vol.r = r

	e, err := r.NextEntry()
	if err != nil {
		t.Fatalf("NextEntry#1: %v", err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("reading the first member: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Entry.Close: %v", err)
	}

	// From here the next read of the stream closes the Reader underneath the
	// scan, exactly as a context cancellation on another goroutine would.
	vol.armed = true

	_, err = r.NextEntry()
	if !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("NextEntry after a Close landing mid-scan = %v, want "+
			"ErrReaderClosed; the stream's own error must not be reported as "+
			"the archive's condition", err)
	}
	if errors.Is(err, os.ErrClosed) {
		t.Fatalf("NextEntry leaked the stream's error to the caller: %v", err)
	}
}

// Close must reach a stream that is stalled inside its own signature read.
//
// The window this pins is the gap between the channel receive and the volume
// becoming reachable as r.vol. A stream received but not yet published is
// reachable from neither r.vol nor r.volumes, so Close -- which reads exactly
// those two -- could not close it, and never called Close on it at all. That
// is not the documented "your stream's Close must interrupt its own Read"
// limit: stalledVolume models os.File/net.Conn, whose Close DOES interrupt an
// in-flight Read, and it was still never rescued.
//
// Mutation check: move the readSignature call in nextVolume back above
// publishVolume and this deadlocks inside the bubble.
func TestCloseRescuesAStreamStalledInItsSignatureRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Constructed INSIDE the bubble, as every test in this file is: a
		// channel created outside leaves the block non-durable and Wait
		// never returns.
		release := make(chan struct{})
		sv := &stalledVolume{release: release}

		volumes := make(chan io.ReadCloser, 1)
		volumes <- sv
		r := NewReader(volumes)

		result := make(chan error, 1)
		go func() {
			_, err := r.NextEntry()
			result <- err
		}()

		// Blocks durably inside io.ReadFull, which is the state under test.
		synctest.Wait()
		_ = r.Close()

		// No timeout arm: inside a bubble a Close that fails to release is
		// reported as a deadlock, which cannot pass by accident on a slow
		// machine.
		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("NextEntry = %v, want ErrReaderClosed", err)
		}
		if !sv.closed() {
			t.Fatal("the stalled stream was never closed by the library -- " +
				"Close reached neither r.vol nor r.volumes for it")
		}
	})
}

// stalledVolume models an os.File/net.Conn-class stream: its Read blocks
// until released, and its own Close releases it. This is the class Close's
// doc comment says IS rescuable, which is what makes it the right fixture --
// a stream that ignores a concurrent Close would leave the test unable to
// distinguish the library's defect from the stream's limitation.
type stalledVolume struct {
	release  chan struct{}
	mu       sync.Mutex
	didClose bool
}

func (s *stalledVolume) Read(p []byte) (int, error) {
	<-s.release
	return 0, os.ErrClosed
}

func (s *stalledVolume) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.didClose {
		s.didClose = true
		close(s.release)
	}
	return nil
}

func (s *stalledVolume) closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.didClose
}

// Entry.Read reaches the same acquisition site through the splice, so the
// same stall is reachable while a member is mid-stream. This is the case a
// context parameter could never have covered: Entry.Read satisfies io.Reader.
//
// Mutation check: move the readSignature call in nextVolume back above
// publishVolume and this deadlocks in the bubble, same as the NextEntry case.
// It is kept despite sharing that mechanism because "one acquisition site
// covers three callers" is a claim about three callers, and this test is the
// only evidence for the second of them. The third, Reset, is covered by the
// traversal-goroutine contract rather than by any test.
func TestCloseRescuesASpliceStalledInASignatureRead(t *testing.T) {
	v1 := rar5Archive(t, false, rar5Member(t, memberSpec{
		name: "split.bin", content: "aaaa",
		unpackedSz: new(int64(8)), packedSz: new(int64(4)), notLast: true,
	}))
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		sv := &stalledVolume{release: release}

		volumes := make(chan io.ReadCloser, 2)
		volumes <- &mockReadCloser{bytes.NewReader(v1)}
		volumes <- sv

		r := NewReader(volumes)
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}

		result := make(chan error, 1)
		go func() {
			_, err := io.ReadAll(e)
			result <- err
		}()

		synctest.Wait()
		_ = r.Close()

		if err := <-result; !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("Entry.Read = %v, want ErrReaderClosed", err)
		}
		if !sv.closed() {
			t.Fatal("the continuation volume stalled in its signature read " +
				"was never closed by the library")
		}
	})
}
