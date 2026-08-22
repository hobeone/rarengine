package rarengine

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// TestRAR3_HeaderParsing exercises ReadRAR3BlockHeader and ParseRAR3FileHeader
// against the real vendored fixture rar3_testfile.rar. This is the only test
// covering these functions that are kept specifically for external consumers
// like gonzbd's internal/rarheader. The fixture is PPMd-compressed and cannot
// be decompressed by this library, so the test is header-only: it parses the
// structure and validates parsed values without attempting decompression.
func TestRAR3_HeaderParsing(t *testing.T) {
	data, err := os.ReadFile("testdata/rar3_testfile.rar")
	if err != nil {
		t.Fatalf("Failed to read fixture: %v", err)
	}

	r := bytes.NewReader(data)

	// Skip the 7-byte RAR3 signature
	sig := make([]byte, 7)
	_, err = io.ReadFull(r, sig)
	if err != nil {
		t.Fatalf("Failed to read signature: %v", err)
	}

	// Expected values from the fixture
	const (
		expectedFileName        = "testfile.txt"
		expectedUnpacked        = 12
		expectedPacked          = 27
		expectedCRC      uint32 = 0x6ec18ffe
	)

	// Track whether we found the file block
	fileBlockFound := false

	// Loop through blocks and validate
	blockCount := 0
	for {
		blockCount++
		if blockCount > 10 {
			t.Fatal("Loop limit exceeded; possible infinite loop")
		}

		h, err := ReadRAR3BlockHeader(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("ReadRAR3BlockHeader failed: %v", err)
		}

		// Guard against negative packed size (the way gonzbd does it)
		if h.DataSize < 0 {
			t.Fatalf("Block header declares negative DataSize: %d", h.DataSize)
		}

		// Block type 0x74 is file header
		if h.Type == 0x74 {
			fh, err := ParseRAR3FileHeader(h)
			if err != nil {
				t.Fatalf("ParseRAR3FileHeader failed: %v", err)
			}

			// Assert concrete parsed values
			if fh.Name != expectedFileName {
				t.Errorf("Name: got %q, want %q", fh.Name, expectedFileName)
			}
			if fh.UnpackedSize != expectedUnpacked {
				t.Errorf("UnpackedSize: got %d, want %d", fh.UnpackedSize, expectedUnpacked)
			}
			if fh.PackedSize != expectedPacked {
				t.Errorf("PackedSize: got %d, want %d", fh.PackedSize, expectedPacked)
			}
			if fh.CRC32 != expectedCRC {
				t.Errorf("CRC32: got 0x%08x, want 0x%08x", fh.CRC32, expectedCRC)
			}

			fileBlockFound = true
		}

		// Skip the block's payload by its declared size. io.CopyN reports
		// io.EOF exactly when it copied FEWER than the requested bytes, so
		// tolerating it here would accept a block whose declared payload runs
		// past the end of the fixture: the header read at the top of the loop
		// would then hit a clean io.EOF, break, and let this test pass on a
		// truncated archive with fileBlockFound already set. An exact-length
		// final block returns nil rather than io.EOF, so there is no
		// legitimate short copy to tolerate.
		if h.DataSize > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(h.DataSize)); err != nil {
				t.Fatalf("Failed to skip the declared %d-byte payload of block "+
					"type 0x%02x: %v", h.DataSize, h.Type, err)
			}
		}
	}

	if !fileBlockFound {
		t.Fatal("File block (type 0x74) not found in fixture")
	}
}
