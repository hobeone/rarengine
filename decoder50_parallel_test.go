package rarengine

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeWith returns the outcomes for every fixture with workers decode
// goroutines (1 is the serial path).
// It also returns how many blocks went through the pipeline.
func decodeWith(t *testing.T, workers int) ([]decodeOutcome, int) {
	t.Helper()
	var readers []*Reader
	out := decodeAll(t, goldenFixtures(t), func(r *Reader) {
		readers = append(readers, r)
		r.SetWorkers(workers)
	})
	blocks := 0
	for _, r := range readers {
		blocks += pipelineBlocks(r)
	}
	return out, blocks
}

// Every fixture decodes identically through the pipeline and the serial
// path: same bytes, same byte counts, same errors, member for member.
// Mutation check: drop the deferred-error rule (surface pendingErr as soon
// as readAhead sees it) and the truncated fixtures differ in byte count.
func TestParallelMatchesSerialOnEveryFixture(t *testing.T) {
	serial, serialBlocks := decodeWith(t, 1)
	if serialBlocks != 0 {
		t.Fatalf("the serial path sent %d blocks through the pipeline", serialBlocks)
	}
	for _, workers := range []int{2, 4} {
		par, blocks := decodeWith(t, workers)
		if blocks == 0 {
			t.Fatalf("workers=%d: no block went through the pipeline; the comparison was serial against serial", workers)
		}
		if len(par) != len(serial) {
			t.Fatalf("workers=%d: %d outcomes, serial %d", workers, len(par), len(serial))
		}
		for i := range serial {
			if par[i].line() != serial[i].line() {
				t.Errorf("workers=%d outcome %d\n par: %s\nserial: %s", workers, i, par[i].line(), serial[i].line())
			}
		}
	}
}

// corruptVariants yields deterministic single-byte corruptions and
// truncations of a fixture. Most land in headers and are refused before
// decoding by both paths; the ones that land in block payloads are what
// this is for.
func corruptVariants(t *testing.T, file string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	// Skip the signature and archive header so variants reach members.
	for i := 64; i < len(data); i += max(1, len(data)/120) {
		v := bytes.Clone(data)
		v[i] ^= 0x5A
		out = append(out, v)
	}
	for i := 128; i < len(data); i += max(1, len(data)/20) {
		out = append(out, bytes.Clone(data[:i]))
	}
	return out
}

func outcomesOf(t *testing.T, archive []byte, workers int) []decodeOutcome {
	t.Helper()
	out, _ := outcomesCounted(t, archive, workers)
	return out
}

// outcomesCounted is outcomesOf that also reports how many blocks went
// through the pipeline, so a test can tell that it ran at all.
func outcomesCounted(t *testing.T, archive []byte, workers int) ([]decodeOutcome, int) {
	t.Helper()
	r := readerFor(archive)
	defer r.Close() //nolint:errcheck
	r.SetWorkers(workers)
	out := readOutcomes(r)
	return out, pipelineBlocks(r)
}

// pipelineBlocks is the number of blocks r's decoder has read ahead.
func pipelineBlocks(r *Reader) int {
	if r.dec50.pipe == nil {
		return 0
	}
	return r.dec50.pipe.parallelBlocks
}

// readOutcomes reads every member of r's archive.
func readOutcomes(r *Reader) []decodeOutcome {
	var out []decodeOutcome
	for i := 0; ; i++ {
		e, err := r.NextEntry()
		if errors.Is(err, io.EOF) {
			return out
		}
		o := decodeOutcome{index: i}
		if err != nil {
			o.err = err.Error()
			return append(out, o)
		}
		o.name = e.Header.Name
		var buf bytes.Buffer
		n, rerr := io.Copy(&buf, e)
		o.n = n
		o.sum = fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))
		if rerr != nil {
			o.err = rerr.Error()
		}
		out = append(out, o)
	}
}

// Damaged input decodes identically too: the same bytes before the error
// and the same error, for byte flips and truncations across the fixture.
// This is the bit-for-bit agreement rule on the inputs that matter.
func TestParallelMatchesSerialOnDamagedInput(t *testing.T) {
	for _, file := range []string{"rar5_solid_bench.rar", "rar5_compress.rar", "rar5_solid_stored_mid.rar", "rar5_exe_filter.rar"} {
		variants := corruptVariants(t, filepath.Join("testdata", file))
		blocks := 0
		for vi, v := range variants {
			serial := outcomesOf(t, v, 1)
			par, n := outcomesCounted(t, v, 4)
			blocks += n
			if len(serial) != len(par) {
				t.Fatalf("%s variant %d: %d vs %d outcomes", file, vi, len(serial), len(par))
			}
			for i := range serial {
				if serial[i].line() != par[i].line() {
					t.Errorf("%s variant %d outcome %d\nserial: %s\n   par: %s", file, vi, i, serial[i].line(), par[i].line())
				}
			}
		}
		// rar5_compress.rar holds only stored members and legitimately
		// submits nothing; the others hold compressed ones.
		if file != "rar5_compress.rar" && blocks == 0 {
			t.Errorf("%s: no variant sent a block through the pipeline", file)
		}
	}
}

// A corrupt block header a few blocks ahead surfaces only after the blocks
// before it have been replayed: the byte count before the error equals the
// serial path's. Built by corrupting the header checksum byte of a block near
// the end of the fixture; blockHeaderOffsets locates block headers.
//
// The block must lie past the first fill target (4 MiB of output here): Read
// discards what a failing fill staged, so an error inside the first fill
// delivers nothing on either path and deferral cannot be seen.
func TestParallelDefersReadAheadErrors(t *testing.T) {
	data := fixtureBytes(t, "rar5_solid_bench.rar")
	offsets := blockHeaderOffsets(t, data)
	if len(offsets) < 12 {
		t.Fatalf("need at least 12 blocks, found %d", len(offsets))
	}
	v := bytes.Clone(data)
	v[offsets[len(offsets)-6]+1] ^= 0xFF // the checksum byte of a late block's header
	serial := outcomesOf(t, v, 1)
	par := outcomesOf(t, v, 4)
	if serial[0].err == "" || !strings.Contains(serial[0].err, ErrCorruptDecodeHeader.Error()) {
		t.Fatalf("setup: serial outcome %q does not report the corrupt header", serial[0].err)
	}
	if serial[0].n == 0 {
		t.Fatal("setup: the serial path delivered nothing before the error, so deferral is unobservable")
	}
	if serial[0].line() != par[0].line() {
		t.Fatalf("deferred error differs\nserial: %s\n   par: %s", serial[0].line(), par[0].line())
	}
}

// blockHeaderOffsets returns the archive offsets of each block header in the
// first compressed member, by reading the member's packed bytes through a
// counting reader while the serial decoder parses block heads.
func blockHeaderOffsets(t *testing.T, archive []byte) []int {
	t.Helper()
	r := readerFor(archive)
	defer r.Close() //nolint:errcheck
	e := firstCompressedMember(t, r)
	// The member's packed data begins where the volume's cursor is now;
	// e.src bottoms out on the volume body. Rather than reach into the
	// volume, locate headers by scanning: decode serially, and after each
	// readBlockHeader, search the archive for the payload bytes just read.
	_ = e
	d, win := r.dec50, r.win
	drain := make([]byte, win.size)
	var offsets []int
	from := 0
	for {
		if err := d.readBlockHeader(); err != nil {
			t.Fatalf("readBlockHeader: %v", err)
		}
		at := bytes.Index(archive[from:], d.payloadBuf)
		if at < 0 {
			t.Fatal("payload not found in archive")
		}
		// The header precedes the payload by 2 + bytecount bytes; bytecount
		// is the smallest byte width that holds the payload length.
		bc := 1
		for len(d.payloadBuf) >= 1<<(8*bc) {
			bc++
		}
		offsets = append(offsets, from+at-2-bc)
		from += at + len(d.payloadBuf)
		if d.lastBlock {
			return offsets
		}
		// Decode the block's symbols so the next header is read from the
		// right position, draining the window after each so it never fills.
		for {
			sym, err := d.tables.main.ReadSym(d.br)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("ReadSym: %v", err)
			}
			if err := d.decodeSymbol(win, sym); err != nil {
				t.Fatalf("decodeSymbol: %v", err)
			}
			_, _ = win.Read(drain)
		}
		d.br = nil
	}
}

// A new-tables block whose code-length table is invalid must fail only
// when replay reaches it, and the blocks before it, decoded against the
// previous tables, must come out intact. The code-length table is at the
// start of the payload after the header, so corrupting the first payload
// byte of a block that carries tables hits it.
func TestNewTablesFailingDoesNotDisturbInFlightBlocks(t *testing.T) {
	data := fixtureBytes(t, "rar5_solid_bench.rar")
	offsets := blockHeaderOffsets(t, data)
	// Find a late block that carries new tables (flag 0x80). It must lie past
	// the first fill target, or the failure discards what was staged and
	// nothing is observable; see TestParallelDefersReadAheadErrors.
	target := -1
	for _, off := range offsets[len(offsets)-8:] {
		if data[off]&0x80 != 0 {
			target = off
			break
		}
	}
	if target < 0 {
		t.Fatal("setup: none of the last eight blocks carries new tables")
	}
	bc := int(data[target]>>3)&3 + 1
	v := bytes.Clone(data)
	v[target+2+bc] = 0xFF // first payload byte: the start of the code-length table
	serial := outcomesOf(t, v, 1)
	par := outcomesOf(t, v, 4)
	if serial[0].line() != par[0].line() {
		t.Fatalf("\nserial: %s\n   par: %s", serial[0].line(), par[0].line())
	}
	if serial[0].err == "" {
		t.Fatal("setup: the serial path decoded the corrupted tables without error")
	}
	if serial[0].n == 0 {
		t.Fatal("setup: nothing decoded before the bad tables; choose a later block")
	}
}

// A block larger than maxParallelPayload is decoded inline with the serial
// buffer, not held in a slot. Forced by lowering the limit through a test
// hook, since no fixture has a 4 MiB block.
func TestOversizeBlockIsDecodedInline(t *testing.T) {
	saved := parallelPayloadLimit
	t.Cleanup(func() { parallelPayloadLimit = saved })
	parallelPayloadLimit = 16 << 10 // blocks in the fixture exceed it
	file := []string{filepath.Join("testdata", "rar5_solid_bench.rar")}
	serial := decodeAll(t, file, nil)
	var rd *Reader
	par := decodeAll(t, file, func(r *Reader) { rd = r; r.SetWorkers(4) })
	if len(par) != len(serial) {
		t.Fatalf("%d outcomes, serial %d", len(par), len(serial))
	}
	for i := range serial {
		if serial[i].line() != par[i].line() {
			t.Fatalf("\nserial: %s\n   par: %s", serial[i].line(), par[i].line())
		}
	}
	if rd.dec50.pipe.oversizeBlocks == 0 {
		t.Fatal("no block was read as oversize: the inline path was not exercised")
	}
}

// A block that is read into the serial buffer and then fails to read in full
// must not leave its slot pointing at that buffer: nothing pops a job that
// never entered the ring, and the next member's blocks would be read into
// the slot's payload, which is the serial buffer. The member after the
// failure must decode exactly as it does serially.
// Mutation check: assign j.payload = d.payloadBuf before the payload read,
// as the oversize path first did, and the alias assertion fails.
func TestOversizeReadFailureDoesNotLeaveSlotAliased(t *testing.T) {
	saved := parallelPayloadLimit
	t.Cleanup(func() { parallelPayloadLimit = saved })
	parallelPayloadLimit = 16 << 10

	data := fixtureBytes(t, "rar5_solid_bench.rar")
	offsets := blockHeaderOffsets(t, data)
	if len(offsets) < 4 {
		t.Fatalf("need at least 4 blocks, found %d", len(offsets))
	}
	noAlias := func(t *testing.T, r *Reader) {
		t.Helper()
		p := r.dec50.pipe
		if p.oversizeBlocks == 0 {
			t.Fatal("setup: no block took the oversize path")
		}
		if p.count != 0 {
			t.Fatalf("setup: %d jobs still in the ring after the member failed", p.count)
		}
		for i, j := range p.slots {
			if len(j.payload) > 0 && len(r.dec50.payloadBuf) > 0 && &j.payload[0] == &r.dec50.payloadBuf[0] {
				t.Fatalf("slot %d still aliases the serial payload buffer", i)
			}
		}
	}

	t.Run("truncated payload", func(t *testing.T) {
		bc := int(data[offsets[3]]>>3)&3 + 1
		cut := offsets[3] + 2 + bc + 100 // inside the fourth block's payload
		if cut >= offsets[4] {
			t.Fatalf("setup: cut %d is not inside block 3 (next block at %d)", cut, offsets[4])
		}

		r := readerFor(data[:cut])
		defer r.Close() //nolint:errcheck
		r.SetWorkers(4)
		failed := readOutcomes(r)
		if len(failed) == 0 || failed[0].err == "" {
			t.Fatalf("setup: the truncated archive did not fail: %v", failed)
		}
		noAlias(t, r)

		r.Reset(volumesOf(data))
		got := readOutcomes(r)
		want := outcomesOf(t, data, 1)
		if len(got) != len(want) {
			t.Fatalf("%d outcomes, serial %d", len(got), len(want))
		}
		for i := range want {
			if got[i].line() != want[i].line() {
				t.Errorf("outcome %d\n par: %s\nserial: %s", i, got[i].line(), want[i].line())
			}
		}
	})

	// The payload is read in full and the block's tables then fail to load.
	// The error is deferred as any read-ahead error is, and the slot that
	// was lent the serial buffer must not keep it.
	t.Run("corrupt tables", func(t *testing.T) {
		target := -1
		for i := 1; i+1 < len(offsets); i++ {
			size := offsets[i+1] - offsets[i]
			if data[offsets[i]]&0x80 != 0 && size > parallelPayloadLimit {
				target = offsets[i]
				break
			}
		}
		if target < 0 {
			t.Fatal("setup: no oversize block after the first carries new tables")
		}
		bc := int(data[target]>>3)&3 + 1
		v := bytes.Clone(data)
		v[target+2+bc] = 0xFF // first payload byte: the start of the code-length table
		serial := outcomesOf(t, v, 1)
		if serial[0].err == "" {
			t.Fatal("setup: the serial path decoded the corrupted tables without error")
		}

		r := readerFor(v)
		defer r.Close() //nolint:errcheck
		r.SetWorkers(4)
		got := readOutcomes(r)
		if len(got) == 0 || got[0].line() != serial[0].line() {
			t.Fatalf("\nserial: %s\n   par: %v", serial[0].line(), got)
		}
		noAlias(t, r)
	})
}
