package rarengine

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func goroutinesSettle(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("goroutines: %d, want at most %d", runtime.NumGoroutine(), want)
}

// Close stops the workers and a Close after Close is harmless.
// Mutation check: make stop skip closing quit and this hangs (the workers
// never exit, so Wait never returns). The wg.Wait itself is pinned by
// TestCloseWhileWaitingForWorkers.
func TestCloseStopsDecodeWorkers(t *testing.T) {
	base := runtime.NumGoroutine()
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := e.Read(buf); err != nil {
		t.Fatal(err)
	}
	if runtime.NumGoroutine() < base+4 {
		t.Fatalf("workers not running: %d goroutines, baseline %d", runtime.NumGoroutine(), base)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	goroutinesSettle(t, base)
}

// Close from another goroutine while the traversal goroutine is inside a
// Read that waits for a worker: the Read returns ErrReaderClosed and the
// workers exit. The worker is held by a job that never completes until
// released, through the test hook on decodeBlockItems.
// Mutation check: make wait receive on j.done alone and this hangs (the
// test's own timeout catches it).
func TestCloseWhileWaitingForWorkers(t *testing.T) {
	base := runtime.NumGoroutine()
	release := make(chan struct{})
	saved := decodeHook
	decodeHook = func() { <-release }
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(func() { decodeHook = saved; unblock() })

	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(2)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, e)
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the traversal goroutine block in wait
	// Close waits for the held workers, so it runs aside; the Read must be
	// released by quit alone, while the workers are still held.
	closeErr := make(chan error, 1)
	go func() { closeErr <- r.Close() }()
	select {
	case err := <-readErr:
		if !errors.Is(err, ErrReaderClosed) {
			t.Fatalf("Read after Close = %v, want ErrReaderClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after Close")
	}
	select {
	case err := <-closeErr:
		t.Fatalf("Close returned (%v) while workers were still decoding", err)
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	if err := <-closeErr; err != nil {
		t.Fatal(err)
	}
	goroutinesSettle(t, base)
}

// A member abandoned with jobs in flight: NextEntry moves on, the next
// compressed member decodes correctly, and no worker is still writing a
// slot the new member reuses (the race detector is the oracle; run with
// -race -count=100).
func TestAbandonedMemberDrainsInFlightJobs(t *testing.T) {
	file := filepath.Join("testdata", "rar5_abandon_large.rar")
	want := decodeAll(t, []string{file}, nil)
	if len(want) != 2 {
		t.Fatalf("fixture has %d members, want 2", len(want))
	}
	r := NewReader(fileVolumesOf(t, file))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// The first member is abandoned with its ring full of jobs.
	e, err = r.NextEntry()
	if err != nil {
		t.Fatalf("after abandon, NextEntry: %v", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, e)
	if err != nil {
		t.Fatalf("after abandon: %v", err)
	}
	if n != want[1].n || hex.EncodeToString(h.Sum(nil)) != want[1].sum {
		t.Fatal("member after abandon differs from the serial decode")
	}
}

// holdWorkers makes every decode worker wait until unblock is called.
func holdWorkers(t *testing.T) (unblock func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock = func() { once.Do(func() { close(release) }) }
	saved := decodeHook
	decodeHook = func() { <-release }
	t.Cleanup(func() { decodeHook = saved; unblock() })
	return unblock
}

// Reset revives a closed Reader's pipeline, including when Close left jobs
// queued that no worker ever took: the next member must neither hang on them
// nor see their results.
// Mutation check: make restart skip waiting and releasing the ring and the
// decode after Reset hangs on a job nobody completes (about half the runs).
func TestResetRevivesWorkersAfterClose(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	want := decodeAll(t, []string{file}, nil)
	unblock := holdWorkers(t)
	r := NewReader(fileVolumesOf(t, file))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(2)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	readErr := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, e)
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // the workers hold two jobs, two more are queued
	closeErr := make(chan error, 1)
	go func() { closeErr <- r.Close() }()
	if err := <-readErr; !errors.Is(err, ErrReaderClosed) {
		t.Fatalf("Read after Close = %v, want ErrReaderClosed", err)
	}
	unblock()
	if err := <-closeErr; err != nil {
		t.Fatal(err)
	}
	r.Reset(fileVolumesOf(t, file))
	res := make(chan error, 1)
	go func() {
		e, err := r.NextEntry()
		if err != nil {
			res <- err
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, e)
		if err == nil && (n != want[0].n || hex.EncodeToString(h.Sum(nil)) != want[0].sum) {
			err = errors.New("decode after Reset differs from the serial decode")
		}
		res <- err
	}()
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("decode after Reset: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("decode after Reset hung")
	}
}

// A Close that lands between member setup steps leaves a quit that has
// fired. engage must not start workers on it, restart must renew it even
// though nothing is running, and a second stop must not close it again.
// Mutation check: let start run workers on a closed quit and the assertion
// "start ran workers on a quit that had fired" fails.
func TestStopEngageRestartStopDoesNotPanic(t *testing.T) {
	base := runtime.NumGoroutine()
	p := newBlockPipeline(2)
	p.start()
	p.stop()
	p.start() // what engage does after a Close that raced the member's setup
	if p.running {
		t.Fatal("start ran workers on a quit that had fired")
	}
	p.restart()
	p.start()
	if !p.running {
		t.Fatal("start after restart did not run workers")
	}
	p.stop()
	p.stop()
	goroutinesSettle(t, base)
}

// The same sequence through the Reader: Close, Reset, decode, Close twice.
func TestCloseResetDecodeCloseTwice(t *testing.T) {
	base := runtime.NumGoroutine()
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	r := NewReader(fileVolumesOf(t, file))
	r.SetWorkers(2)
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	r.Reset(fileVolumesOf(t, file))
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("decode after Reset: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	goroutinesSettle(t, base)
}

// Entry.Read allocates nothing in steady state through the pipeline: the
// slots, items, payload buffers and table sets are allocated when the
// pipeline starts, and the first member grows the payload buffers once.
// Mutation check: allocate a fresh item slice per block in decodeBlockItems
// and the count is non-zero.
func TestParallelReadDoesNotAllocate(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	r := NewReader(fileVolumesOf(t, file))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(4)
	// Warm: first member grows every buffer to this archive's block size.
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	allocs := testing.AllocsPerRun(3, func() {
		r.Reset(fileVolumesOf(t, file))
		e, err := r.NextEntry()
		if err != nil {
			t.Fatal(err)
		}
		for {
			_, err := e.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	// Reset and NextEntry allocate for the new volume and header; measure
	// Read alone by subtracting a run that reads nothing.
	base := testing.AllocsPerRun(3, func() {
		r.Reset(fileVolumesOf(t, file))
		if _, err := r.NextEntry(); err != nil {
			t.Fatal(err)
		}
	})
	if allocs-base > 0 {
		t.Fatalf("Read allocated %.0f times per member through the pipeline", allocs-base)
	}
}

// A Close that lands before the pipeline has started (the first compressed
// member, or the first one after Reset) must still stop the workers that
// engage starts afterwards: nothing else would, until a later Close or Reset.
// Mutation check: make stop return early when !running, as it did, and both
// assertions fail.
func TestStopBeforeStartPreventsWorkers(t *testing.T) {
	base := runtime.NumGoroutine()
	p := newBlockPipeline(2)
	p.stop() // Close lands before the pipeline ever ran
	p.start()
	if p.running {
		t.Fatal("start ran workers after a stop that preceded it")
	}
	if g := runtime.NumGoroutine(); g > base {
		t.Fatalf("%d goroutines, baseline %d", g, base)
	}
	p.stop() // a second stop must not close quit again
	p.restart()
	p.start()
	if !p.running {
		t.Fatal("start after restart did not run workers")
	}
	p.stop()
	goroutinesSettle(t, base)
}

// closeAfter is a volume that closes the Reader from inside the Read that
// crosses byte offset at, so the Close lands at a fixed point of NextEntry.
type closeAfter struct {
	io.Reader
	r    *Reader
	at   int
	read int
}

func (c *closeAfter) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	before := c.read
	c.read += n
	if before < c.at && c.read >= c.at {
		_ = c.r.Close()
	}
	return n, err
}

func (c *closeAfter) Close() error { return nil }

// The same through the Reader: after a Close and a Reset the pipeline exists
// but is not running, and a Close landing anywhere inside the next NextEntry,
// including between the pipeline being chosen and engage starting it, must
// leave no workers behind. Sweeping the byte offset at which the Close fires
// covers the whole header and the start of the payload deterministically.
// Mutation check: as above; the offsets that land before engage leave workers
// running on a closed Reader.
func TestCloseDuringNextEntryLeavesNoWorkers(t *testing.T) {
	file := filepath.Join("testdata", "rar5_solid_bench.rar")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	base := runtime.NumGoroutine()
	r := NewReader(fileVolumesOf(t, file))
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatal(err)
	}
	for at := range 400 {
		_ = r.Close() // pipeline exists, stopped
		vols := make(chan io.ReadCloser, 1)
		vols <- &closeAfter{Reader: bytes.NewReader(data), r: r, at: at}
		close(vols)
		r.Reset(vols) // restart: pipeline exists, not running, quit open
		_, _ = r.NextEntry()
		if chanClosed(r.done) && r.dec50.pipe.running {
			t.Fatalf("Close at offset %d left decode workers running", at)
		}
	}
	_ = r.Close()
	goroutinesSettle(t, base)
}

// SetWorkers is latched per member: changing it mid-member has no effect
// until the next member, and n above maxWorkers is clamped.
func TestSetWorkersTakesEffectAtTheNextMember(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_abandon_large.rar")))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	r.SetWorkers(64)
	if r.dec50.pipe != nil {
		t.Fatal("SetWorkers engaged a pipeline for the member already in progress")
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatal(err)
	}
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	if r.dec50.pipe == nil || r.dec50.pipe.workers != maxWorkers {
		t.Fatalf("next member: pipe=%v, want %d workers", r.dec50.pipe, maxWorkers)
	}
}
