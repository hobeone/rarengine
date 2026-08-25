package rarengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
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
		name: "split.bin", content: "aaaa", unpackedSz: 8, packedSz: 4, notLast: true,
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
// Mutation check: replace the guarded closed flag with an unsynchronised
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
