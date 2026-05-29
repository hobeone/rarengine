package rarengine

import (
	"io"
	"sync"
)

const defaultVolumeChunkSize = 64 * 1024

// BufferedVolume wraps src in an io.ReadCloser that pumps bytes through a
// background goroutine, allowing volume I/O to overlap with the decompressor's
// CPU-bound work.
//
// Up to bufferBytes of read-ahead is held in fixed-size chunks. When the
// buffer is full the producer goroutine blocks; when empty the consumer
// blocks. Close stops the producer and closes src.
//
// Typical use for a multi-volume archive:
//
//	volumesChan := make(chan io.ReadCloser, 2)
//	go func() {
//	    defer close(volumesChan)
//	    for _, path := range volumePaths {
//	        f, err := os.Open(path)
//	        if err != nil { /* ... */ }
//	        volumesChan <- rarengine.BufferedVolume(f, 8<<20)
//	    }
//	}()
//	sd := rarengine.NewStreamDecompressor(volumesChan)
//
// The gains are largest when src has nontrivial latency (network sockets,
// throttled disks). For warm local files the OS already does read-ahead, so
// the benefit is modest.
//
// The returned ReadCloser is not safe for concurrent Read/Close from multiple
// goroutines, matching the standard io.Reader contract.
func BufferedVolume(src io.ReadCloser, bufferBytes int) io.ReadCloser {
	chunks := bufferBytes / defaultVolumeChunkSize
	if chunks < 2 {
		chunks = 2
	}
	bv := &bufferedVolume{
		chunks: make(chan []byte, chunks),
		stop:   make(chan struct{}),
		src:    src,
	}
	go bv.pump(defaultVolumeChunkSize)
	return bv
}

type bufferedVolume struct {
	chunks chan []byte
	stop   chan struct{}
	cur    []byte
	src    io.ReadCloser

	// err is set by pump before close(chunks); the consumer reads it only
	// after the closed-channel receive, which provides happens-before.
	err error

	closeOnce sync.Once
	closeErr  error
}

func (bv *bufferedVolume) pump(chunkSize int) {
	defer close(bv.chunks)
	for {
		buf := make([]byte, chunkSize)
		n, err := bv.src.Read(buf)
		if n > 0 {
			select {
			case bv.chunks <- buf[:n]:
			case <-bv.stop:
				return
			}
		}
		if err != nil {
			bv.err = err
			return
		}
	}
}

func (bv *bufferedVolume) Read(p []byte) (int, error) {
	if len(bv.cur) == 0 {
		chunk, ok := <-bv.chunks
		if !ok {
			if bv.err != nil && bv.err != io.EOF {
				return 0, bv.err
			}
			return 0, io.EOF
		}
		bv.cur = chunk
	}
	n := copy(p, bv.cur)
	bv.cur = bv.cur[n:]
	return n, nil
}

func (bv *bufferedVolume) Close() error {
	bv.closeOnce.Do(func() {
		// Close src first so any in-flight src.Read returns. Then signal the
		// pump to stop (in case it's blocked on a send) and drain whatever
		// chunks remain so pump can exit cleanly.
		bv.closeErr = bv.src.Close()
		close(bv.stop)
		for range bv.chunks {
		}
	})
	return bv.closeErr
}
