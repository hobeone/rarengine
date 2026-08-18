package rarengine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"testing"
)

// writeVarBytes emits the shape readFilter5Data parses: a 2-bit count of value
// bytes, followed by that many little-endian bytes.
func writeVarBytes(bw *bitWriter, value int64) {
	n := 1
	for v := value >> 8; v > 0; v >>= 8 {
		n++
	}
	bw.writeBits(uint32(n-1), 2)
	for i := range n {
		bw.writeBits(uint32((value>>uint(8*i))&0xff), 8)
	}
}

// encodeFilter renders one filter record as readFilter parses it.
// Values are int64 so a four-byte record with the top bit set can be built on
// 32-bit platforms, where such a constant overflows int.
func encodeFilter(rawOffset, length int64, ftype, param int) []byte {
	var bw bitWriter
	writeVarBytes(&bw, rawOffset)
	writeVarBytes(&bw, length)
	bw.writeBits(uint32(ftype), 3)
	if ftype == 0 {
		bw.writeBits(uint32(param-1), 5)
	}
	bw.flush()
	return bw.buf
}

// queueOne parses a single filter record into d's queue from a synthesized
// stream, returning readFilter's error.
func queueOne(d *decoder50, win *Window, rawOffset, length int64, ftype, param int) error {
	d.br = NewBitReader(encodeFilter(rawOffset, length, ftype, param), 96)
	return d.readFilter(win)
}

// drainedDecoder returns a decoder whose fill can make no further progress, so
// Read is driven purely by what the window already holds.
func drainedDecoder() *decoder50 {
	d := newDecoder50()
	d.r = bytes.NewReader(nil)
	d.lastBlock = true
	return d
}

// TestFilterDrain covers filters firing at the right output positions.
//
// wantFired is the assertion that matters; wantReads pins the boundaries Read
// returns on, since a filter application and a passthrough are separate calls.
func TestFilterDrain(t *testing.T) {
	tests := []struct {
		name      string
		payload   int
		filters   []FilterBlock
		wantReads []int
		wantFired []int
	}{
		{
			name:    "three filters telescoping",
			payload: 70,
			filters: []FilterBlock{
				{start: 10, length: 20, ftype: 0, param: 1},
				{start: 45, length: 5, ftype: 0, param: 1},
				{start: 60, length: 10, ftype: 0, param: 1},
			},
			wantReads: []int{10, 20, 15, 5, 10, 10},
			wantFired: []int{10, 45, 60},
		},
		{
			name:    "two filters",
			payload: 80,
			filters: []FilterBlock{
				{start: 10, length: 20, ftype: 0, param: 1},
				{start: 45, length: 5, ftype: 0, param: 1},
			},
			wantReads: []int{10, 20, 15, 5},
			wantFired: []int{10, 45},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := drainedDecoder()
			win := NewWindow(0x40000)

			payload := make([]byte, tc.payload)
			for i := range payload {
				payload[i] = byte(i)
			}
			win.writeBytes(payload)
			d.fl = append(d.fl, tc.filters...)

			var gotReads, gotFired []int
			var cursor int
			p := make([]byte, 128)
			for range len(tc.wantReads) {
				queued := len(d.fl)
				n, err := d.Read(win, p)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				if len(d.fl) < queued {
					gotFired = append(gotFired, cursor)
				}
				gotReads = append(gotReads, n)
				cursor += n
			}

			if !slices.Equal(gotReads, tc.wantReads) {
				t.Errorf("read sizes = %v, want %v", gotReads, tc.wantReads)
			}
			if !slices.Equal(gotFired, tc.wantFired) {
				t.Errorf("filters fired at %v, want %v", gotFired, tc.wantFired)
			}
			if len(d.fl) != 0 {
				t.Errorf("%d filters left queued, want 0", len(d.fl))
			}
		})
	}
}

// TestFilterPassthroughOffsetPersists is the regression test for the reported
// defect: the head filter's offset must decrement across Read calls so the
// passthrough terminates and the filter actually fires.
func TestFilterPassthroughOffsetPersists(t *testing.T) {
	d := drainedDecoder()
	win := NewWindow(0x40000)
	win.writeBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	d.fl = append(d.fl, FilterBlock{start: 4, length: 4, ftype: 0, param: 1})

	var got []byte
	for range 8 {
		p := make([]byte, 2)
		n, err := d.Read(win, p)
		if err != nil || n == 0 {
			break
		}
		got = append(got, p[:n]...)
	}

	if len(d.fl) != 0 {
		t.Fatalf("filter never fired: %d still queued, head start %d", len(d.fl), d.fl[0].start)
	}
	// First four bytes pass through untouched; the rest are delta-filtered and
	// so must differ from the raw input.
	if !bytes.Equal(got[:4], []byte{1, 2, 3, 4}) {
		t.Errorf("passthrough = %v, want [1 2 3 4]", got[:4])
	}
	if bytes.Equal(got[4:], []byte{5, 6, 7, 8}) {
		t.Errorf("filtered range was emitted unmodified: %v", got[4:])
	}
}

// TestReadFilterAbsoluteStart covers the queue-time position: a filter starts
// its raw offset past the decode head, independent of where the ring's read and
// write indices happen to sit. Driving it with a wrapped window (win.r > win.w)
// pins that independence — the previous encoding derived the position from the
// index difference and had to correct for the wrap.
func TestReadFilterAbsoluteStart(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)
	win.r = win.size - 44
	win.w = 44
	d.decoded = 1000

	if err := queueOne(d, win, 30, 20, 0, 1); err != nil {
		t.Fatalf("first readFilter: %v", err)
	}

	d.decoded += 100

	if err := queueOne(d, win, 5, 20, 0, 1); err != nil {
		t.Fatalf("second readFilter: %v", err)
	}

	if len(d.fl) != 2 {
		t.Fatalf("queued %d filters, want 2", len(d.fl))
	}
	if d.fl[0].start != 1030 {
		t.Errorf("first start = %d, want 1030 (decoded 1000 + raw 30)", d.fl[0].start)
	}
	if d.fl[1].start != 1105 {
		t.Errorf("second start = %d, want 1105 (decoded 1100 + raw 5)", d.fl[1].start)
	}
}

// TestReadFilterRejectsOutOfOrderStart covers a filter queued behind one
// already in the queue.
func TestReadFilterRejectsOutOfOrderStart(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)
	d.decoded = 1000

	if err := queueOne(d, win, 50, 10, 0, 1); err != nil {
		t.Fatalf("first readFilter: %v", err)
	}
	// The decode head has not moved, so a smaller raw offset places this block
	// before the one already queued.
	if err := queueOne(d, win, 10, 10, 0, 1); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter", err)
	}
}

// TestFilterRejectsOverlap covers a filter that would have to be applied to the
// previous block's output rather than to fresh window data.
func TestFilterRejectsOverlap(t *testing.T) {
	d := drainedDecoder()
	win := NewWindow(0x40000)
	win.writeBytes(make([]byte, 64))

	d.fl = append(d.fl,
		FilterBlock{start: 0, length: 20, ftype: 0, param: 1},
		FilterBlock{start: 10, length: 20, ftype: 0, param: 1},
	)

	p := make([]byte, 128)
	if _, err := d.Read(win, p); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter", err)
	}
}

// TestStageFilterInputTruncated covers a filter block the stream cannot
// satisfy. The staging read must not leave stale bytes in the reusable buffer,
// and must not surface a clean EOF.
func TestStageFilterInputTruncated(t *testing.T) {
	d := drainedDecoder()
	win := NewWindow(0x40000)
	win.writeBytes(bytes.Repeat([]byte{0xBB}, 8))

	// Pre-dirty the staging buffer the way a previous larger block would.
	d.filterBuf = bytes.Repeat([]byte{0xAA}, 64)
	d.fl = append(d.fl, FilterBlock{start: 0, length: 64, ftype: 1})

	p := make([]byte, 128)
	n, err := d.Read(win, p)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	if n != 0 {
		t.Errorf("returned %d bytes alongside the error, want 0", n)
	}
	// Scan the whole caller buffer, not p[:n]: with n == 0 that slice is empty
	// and the check would hold vacuously. p is zero-valued on entry, so any
	// 0xAA in it was written by the filter path regardless of the count
	// returned.
	if i := bytes.IndexByte(p, 0xAA); i >= 0 {
		t.Errorf("stale byte from the previous block reached the output at index %d", i)
	}
	if len(d.outbuf) != 0 {
		t.Errorf("%d bytes left staged for a later Read", len(d.outbuf))
	}
}

// TestReadFilterRejectsOversize covers the block-length cap.
func TestReadFilterRejectsOversize(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)

	err := queueOne(d, win, 0, int64(maxFilterBlockSize)+1, 0, 1)
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter", err)
	}
	if len(d.fl) != 0 {
		t.Errorf("oversize filter was queued")
	}
}

// TestReadFilterRejectsOversizeOffset covers the offset bound. readFilter5Data
// can yield up to 0xFFFFFFFF, and a filter announced more than a window away
// from the decode head is malformed.
func TestReadFilterRejectsOversizeOffset(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)

	err := queueOne(d, win, int64(win.size)+1, 8, 0, 1)
	if !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("err = %v, want ErrInvalidFilter", err)
	}
	if len(d.fl) != 0 {
		t.Errorf("filter with an oversize offset was queued")
	}
}

// TestDecodedTracksOutput covers the counter filter positions are anchored to.
// decoded must equal the bytes a file actually produces, or every queued filter
// lands at the wrong offset — a drift no position test would attribute to the
// counter.
func TestDecodedTracksOutput(t *testing.T) {
	f, err := os.Open("testdata/rar5_exe_filter.rar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	volumes := make(chan io.ReadCloser, 1)
	volumes <- f
	close(volumes)

	sd := NewStreamDecompressor(volumes)
	h, err := sd.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	n, err := io.Copy(io.Discard, sd)
	if err != nil {
		t.Fatalf("draining: %v", err)
	}

	re, ok := sd.engine.(*rar5Engine)
	if !ok {
		t.Fatalf("engine is %T, want *rar5Engine", sd.engine)
	}
	if re.dec50.decoded != n {
		t.Errorf("decoded = %d, want %d (bytes emitted)", re.dec50.decoded, n)
	}
	if n != h.UnpackedSize {
		t.Errorf("emitted %d bytes, header says %d", n, h.UnpackedSize)
	}
}

// TestReadFilter5DataStaysPositive covers a four-byte value with the top bit
// set. Accumulated into an int it is negative on 32-bit platforms, where a
// negative length reaches a slice expression and a negative offset places a
// filter behind the emission cursor. Both bounds in readFilter are upper-only,
// so the type is what keeps them sufficient.
func TestReadFilter5DataStaysPositive(t *testing.T) {
	var bw bitWriter
	writeVarBytes(&bw, 0xF0332211)
	bw.flush()

	val, err := readFilter5Data(NewBitReader(bw.buf, len(bw.buf)*8))
	if err != nil {
		t.Fatalf("readFilter5Data: %v", err)
	}
	if val != 0xF0332211 {
		t.Fatalf("value = %#x, want 0xF0332211", val)
	}
	if val < 0 {
		t.Errorf("value is negative; a length this size would panic a slice expression")
	}
}

// TestReadFilterRejectsHugeValues covers the same value arriving through
// readFilter, where it must be rejected rather than queued.
func TestReadFilterRejectsHugeValues(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)

	if err := queueOne(d, win, 0, 0xF0332211, 0, 1); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("huge length: err = %v, want ErrInvalidFilter", err)
	}
	if err := queueOne(d, win, 0xF0332211, 8, 0, 1); !errors.Is(err, ErrInvalidFilter) {
		t.Errorf("huge offset: err = %v, want ErrInvalidFilter", err)
	}
	if len(d.fl) != 0 {
		t.Errorf("%d filters queued, want 0", len(d.fl))
	}
}

// TestReadFilterDropsZeroLength covers zero-length suppression. Queueing such a
// block would make Read return no bytes and no error against a non-empty
// buffer, violating io.Reader.
func TestReadFilterDropsZeroLength(t *testing.T) {
	d := newDecoder50()
	win := NewWindow(0x40000)

	if err := queueOne(d, win, 0, 0, 0, 1); err != nil {
		t.Fatalf("readFilter: %v", err)
	}
	if len(d.fl) != 0 {
		t.Errorf("zero-length filter was queued")
	}
}
