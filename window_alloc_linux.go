//go:build linux

package rarengine

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// defaultMaxWindow is the cap a Reader starts with. A mapping costs address
// space, not memory, until the stream writes into it, so the format's full
// 4 GiB is affordable here; the heap-backed platforms start lower.
const defaultMaxWindow = maxDictSize

// reserveWindowOS returns a zero-filled buffer of exactly size bytes backed by
// an anonymous private mapping, together with a function that returns it to
// the kernel.
//
// A mapping rather than make for two reasons that are both about the
// dictionary's upper end. RAR5 declares dictionaries up to 4 GiB, and a Go
// slice of that size is heap: make([]byte, 4<<30) leaves HeapAlloc at 4 GiB
// and moves the next GC target to 8 GiB for a buffer that is mostly never
// touched. A mapping is not heap. Its pages are committed by the kernel as the
// stream writes into them, so resident memory follows the history actually
// produced, capped by the dictionary, and the Go runtime neither scans it nor
// counts it. Reserving 4 GiB this way was measured at 3.5 ms.
//
// MAP_NORESERVE asks the kernel not to account the whole reservation against
// overcommit up front, which is what lets a 4 GiB window be reserved on a
// machine that could not commit 4 GiB; the pages that ARE touched are
// accounted as they are touched, like any anonymous memory. A failure here is
// reported rather than papered over: the caller refuses the member as a
// capacity limit, which is the classification its consumers already handle.
func reserveWindowOS(size int) ([]byte, func(), error) {
	buf, err := unix.Mmap(-1, 0, size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE)
	if err != nil {
		return nil, nil, fmt.Errorf("reserving a %d-byte window: %w", size, err)
	}
	return buf, func() { _ = unix.Munmap(buf) }, nil
}

// decommitWindow returns buf's pages to the kernel without giving up the
// reservation, so the next write to any of them faults in a fresh zero page.
//
// Called once per archive from Reader.Reset, never per member. The per-member
// cost that CLAUDE.md forbids was a 32 MiB memclr on every file; this is one
// syscall per archive, and the faults it causes afterwards are the same ones
// the first archive paid to touch those pages at all. What it buys is that a
// long-lived Reader's resident set falls back to nothing between archives,
// instead of staying at whatever the largest dictionary it ever saw committed.
func decommitWindow(buf []byte) {
	_ = unix.Madvise(buf, unix.MADV_DONTNEED)
}
