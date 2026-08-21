package rarengine

import (
	"io"
	"os"
	"testing"
)

// TestVolumePayloadSkipsServiceHeader covers a service record reaching the
// multi-volume payload path, where without the skip its bytes would be spliced
// into the file being reassembled.
//
// rar emits service records after each volume's file block, so the payload
// reader stops at the file block first and rar's own archives never produce
// this layout. A crafted archive can, so the header is driven in directly
// rather than through a fixture.
func TestVolumePayloadSkipsServiceHeader(t *testing.T) {
	f, err := os.Open("testdata/rar5_multi_service.part02.rar")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })

	if _, err := detectVersion(f); err != nil {
		t.Fatalf("detectVersion: %v", err)
	}

	// Walk to the first service header, skipping each block's payload.
	var svc *BlockHeader
	var svcPacked int64
	for {
		h, err := ReadBlockHeader(f)
		if err != nil {
			t.Fatalf("no service header found: %v", err)
		}
		if h.Type == HeaderTypeFile || h.Type == HeaderTypeService {
			fh, ferr := ParseFileHeader(h)
			if ferr != nil {
				t.Fatalf("ParseFileHeader: %v", ferr)
			}
			if h.Type == HeaderTypeService {
				svc, svcPacked = h, fh.PackedSize
				break
			}
			if _, err := io.CopyN(io.Discard, f, fh.PackedSize); err != nil {
				t.Fatalf("skipping file payload: %v", err)
			}
			continue
		}
		if h.DataSize > 0 {
			if _, err := io.CopyN(io.Discard, f, h.DataSize); err != nil {
				t.Fatalf("skipping block payload: %v", err)
			}
		}
	}
	if svcPacked <= 0 {
		t.Fatalf("service record has no payload (%d bytes); it would not exercise the skip", svcPacked)
	}

	// Position a decoder on the stream just past that header and hand it to the
	// payload path.
	sd := NewStreamDecompressor(make(chan io.ReadCloser))
	sd.currentVol = io.NopCloser(f)
	re := newRAR5Engine(sd)

	before, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}

	r, err := re.processVolumePayloadHeader(svc)
	if err != nil {
		t.Fatalf("processVolumePayloadHeader: %v", err)
	}
	if r != nil {
		// One assertion now carries both halves: a non-nil reader would have
		// its bytes spliced into the file as content, and it is also what
		// stops the caller's scan, so the real payload would never be sought.
		t.Error("service record was returned as payload; its bytes would be spliced into the file")
	}

	after, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	if got := after - before; got != svcPacked {
		t.Errorf("consumed %d bytes of the service record, want %d", got, svcPacked)
	}
}
