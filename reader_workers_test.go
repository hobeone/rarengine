package rarengine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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
// Mutation check: make stop skip wg.Wait and the goroutine count stays up.
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
	// Two compressed members in one archive: the far fixtures are single
	// member, so use the solid bench archive twice through Reset.
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	defer r.Close() //nolint:errcheck
	r.SetWorkers(4)
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// Abandon: Reset to the same archive with jobs in flight.
	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	want := decodeAll(t, []string{filepath.Join("testdata", "rar5_solid_bench.rar")}, nil)
	for i := range want {
		e, err := r.NextEntry()
		if err != nil {
			t.Fatalf("after abandon, NextEntry %d: %v", i, err)
		}
		h := sha256.New()
		n, err := io.Copy(h, e)
		if err != nil {
			t.Fatalf("after abandon, member %d: %v", i, err)
		}
		if n != want[i].n || hex.EncodeToString(h.Sum(nil)) != want[i].sum {
			t.Fatalf("after abandon, member %d differs from the serial decode", i)
		}
	}
}

// Reset revives a closed Reader's pipeline.
func TestResetRevivesWorkersAfterClose(t *testing.T) {
	r := NewReader(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	r.SetWorkers(2)
	if _, err := r.NextEntry(); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	r.Reset(fileVolumesOf(t, filepath.Join("testdata", "rar5_solid_bench.rar")))
	defer r.Close() //nolint:errcheck
	e, err := r.NextEntry()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, e); err != nil {
		t.Fatalf("decode after Reset: %v", err)
	}
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
