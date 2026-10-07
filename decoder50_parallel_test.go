package rarengine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// Every fixture decodes identically through the pipeline and the serial
// path: same bytes, same byte counts, same errors, member for member.
// Mutation check: drop the deferred-error rule (surface pendingErr as soon
// as readAhead sees it) and the truncated fixtures differ in byte count.
func TestParallelMatchesSerialOnEveryFixture(t *testing.T) {
	workerCounts := []int{2, 4}
	var serialBlocks atomic.Int64
	blocks := make([]atomic.Int64, len(workerCounts)) // pipeline blocks per worker count
	t.Run("fixtures", func(t *testing.T) {
		for _, file := range goldenFixtures(t) {
			t.Run(filepath.Base(file), func(t *testing.T) {
				t.Parallel()
				serial, sr := decodeFile(t, file, func(r *Reader) { r.SetWorkers(1) })
				serialBlocks.Add(int64(pipelineBlocks(sr)))
				for k, workers := range workerCounts {
					par, pr := decodeFile(t, file, func(r *Reader) { r.SetWorkers(workers) })
					blocks[k].Add(int64(pipelineBlocks(pr)))
					if len(par) != len(serial) {
						t.Errorf("workers=%d: %d outcomes, serial %d", workers, len(par), len(serial))
						continue
					}
					for i := range serial {
						if par[i].line() != serial[i].line() {
							t.Errorf("workers=%d outcome %d\n par: %s\nserial: %s", workers, i, par[i].line(), serial[i].line())
						}
					}
				}
			})
		}
	})
	if n := serialBlocks.Load(); n != 0 {
		t.Errorf("the serial path sent %d blocks through the pipeline", n)
	}
	for k, workers := range workerCounts {
		if blocks[k].Load() == 0 {
			t.Errorf("workers=%d: no block went through the pipeline; the comparison was serial against serial", workers)
		}
	}
}

// damagedVariant is one damaged copy of a fixture and where it was damaged.
type damagedVariant struct {
	name string
	data []byte
}

// withFlip is data with the byte at pos inverted in some bits.
func withFlip(data []byte, pos int) []byte {
	v := bytes.Clone(data)
	v[pos] ^= 0x5A
	return v
}

// randomVariants is a sparse, evenly spread grid over a fixture: 20
// single-byte flips and 6 truncations, at fixed positions so a failure
// reproduces. It skips the signature and archive header so variants reach
// members. Most land in headers and are refused before decoding by both
// paths; it is a net for the places targetedVariants does not name.
func randomVariants(data []byte) []damagedVariant {
	var out []damagedVariant
	for k := range 20 {
		pos := 64 + k*(len(data)-64)/20
		out = append(out, damagedVariant{fmt.Sprintf("flip@%d", pos), withFlip(data, pos)})
	}
	for k := range 6 {
		cut := 128 + k*(len(data)-128)/6
		out = append(out, damagedVariant{fmt.Sprintf("cut@%d", cut), bytes.Clone(data[:cut])})
	}
	return out
}

// targetedVariants damages every block of every compressed member of the
// fixture at the seams the parallel path introduces. Per block it makes:
//
//   - badflags and badsum: the flags byte, and the checksum byte, inverted.
//     Either way the header checksum no longer matches, so both are the same
//     refusal of a header while it is read ahead, whose error must wait for
//     the blocks before it.
//   - newtables and lastblock: the flags byte with the new-tables bit, or the
//     last-block bit, toggled and the checksum byte corrected to match, so the
//     header parses and the block is decoded with the opposite
//     newTables/lastBlock semantics (tables loaded from bytes that are not a
//     table, or not loaded; the member ended early, or not at all).
//   - firstbyte: the first payload byte inverted, the start of the
//     code-length table when the block carries one: a table that fails to
//     load while earlier blocks are still decoding against the previous one.
//   - lastbyte: the last payload byte inverted, which corrupts the block's
//     final bits (usually its last symbol) at the end of a job. It does not
//     shorten the payload; the cuts below do that.
//
// It truncates at each block boundary, one byte before and one byte after
// (a job whose payload or header is incomplete, and the deferred end-of-data
// error that follows the last complete block). The boundaries are the places
// where one job ends and the next begins, so they are where a disagreement
// between a worker's view and the serial decoder's can hide.
//
// Each offset is checked by parsing the header there with readBlockHead and
// requiring the payload length to match the one the variants are built from.
func targetedVariants(t *testing.T, data []byte) []damagedVariant {
	t.Helper()
	offsets := blockHeaderOffsets(t, data)
	var out []damagedVariant
	var boundaries []int
	var buf [5]byte
	for _, off := range offsets {
		h, err := readBlockHead(bytes.NewReader(data[off:]), &buf)
		if err != nil {
			t.Fatalf("setup: no block header at %d: %v", off, err)
		}
		bc := int(data[off]>>3)&3 + 1
		payloadLen := 0
		for i := range bc {
			payloadLen |= int(data[off+2+i]) << (8 * i)
		}
		if h.blockBytes != payloadLen {
			t.Fatalf("setup: block at %d: parsed payload length %d, offsets say %d", off, h.blockBytes, payloadLen)
		}
		first := off + 2 + bc
		last := first + payloadLen - 1
		if last >= len(data) {
			t.Fatalf("setup: block at %d ends past the archive (%d)", off, len(data))
		}
		boundaries = append(boundaries, off, last+1)
		for _, p := range []struct {
			what string
			pos  int
		}{{"badflags", off}, {"badsum", off + 1}, {"firstbyte", first}, {"lastbyte", last}} {
			out = append(out, damagedVariant{fmt.Sprintf("block@%d/%s", off, p.what), withFlip(data, p.pos)})
		}
		// A flags bit toggled with the checksum byte (0x5a ^ flags ^ the
		// length bytes) moved by the same bit, so the header still parses.
		for _, p := range []struct {
			what string
			bit  byte
		}{{"newtables", 0x80}, {"lastblock", 0x40}} {
			v := bytes.Clone(data)
			v[off] ^= p.bit
			v[off+1] ^= p.bit
			if _, err := readBlockHead(bytes.NewReader(v[off:]), &buf); err != nil {
				t.Fatalf("setup: block@%d/%s does not parse: %v", off, p.what, err)
			}
			out = append(out, damagedVariant{fmt.Sprintf("block@%d/%s", off, p.what), v})
		}
	}
	slices.Sort(boundaries)
	boundaries = slices.Compact(boundaries) // a block's end is often the next block's header
	for _, b := range boundaries {
		for _, d := range []int{-1, 0, 1} {
			if cut := b + d; cut > 0 && cut < len(data) {
				out = append(out, damagedVariant{fmt.Sprintf("cut@%d", cut), bytes.Clone(data[:cut])})
			}
		}
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

// Damaged input decodes identically too: the same bytes before the error
// and the same error, for byte flips and truncations across the fixture.
// This is the bit-for-bit agreement rule on the inputs that matter.
//
// Each variant is its own parallel subtest with its own Readers. Under -short
// only the targeted variants of rar5_sweep.rar run.
func TestParallelMatchesSerialOnDamagedInput(t *testing.T) {
	short := testing.Short()
	if short {
		t.Log("-short: targeted variants of rar5_sweep.rar only")
	}
	for _, f := range []struct {
		file       string
		compressed bool // holds a compressed member, so blocks can be targeted and must engage the pipeline
	}{
		{"rar5_sweep.rar", true},
		{"rar5_exe_filter.rar", true},
		{"rar5_solid_stored_mid.rar", true},
		{"rar5_compress.rar", false}, // stored members only: legitimately submits nothing
	} {
		if short && f.file != "rar5_sweep.rar" {
			continue
		}
		t.Run(f.file, func(t *testing.T) {
			t.Parallel()
			data := fixtureBytes(t, f.file)
			var variants []damagedVariant
			if f.compressed {
				variants = targetedVariants(t, data)
			}
			if !short {
				variants = append(variants, randomVariants(data)...)
			}
			var blocks atomic.Int64
			t.Run("variants", func(t *testing.T) {
				for _, v := range variants {
					t.Run(v.name, func(t *testing.T) {
						t.Parallel()
						serial := outcomesOf(t, v.data, 1)
						par, n := outcomesCounted(t, v.data, 4)
						blocks.Add(int64(n))
						if len(serial) != len(par) {
							t.Fatalf("%d vs %d outcomes", len(serial), len(par))
						}
						for i := range serial {
							if serial[i].line() != par[i].line() {
								t.Errorf("outcome %d\nserial: %s\n   par: %s", i, serial[i].line(), par[i].line())
							}
						}
					})
				}
			})
			// The group above has returned: every variant has finished.
			if f.compressed && blocks.Load() == 0 {
				t.Error("no variant sent a block through the pipeline")
			}
		})
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

// blockHeaderLen is the size of a block header that precedes a payload of
// payloadLen bytes: flags and checksum, then the payload length in the
// smallest byte width that holds it. It is the inverse of readBlockHead.
func blockHeaderLen(payloadLen int) int {
	bc := 1
	for payloadLen >= 1<<(8*bc) {
		bc++
	}
	return 2 + bc
}

// blockHeaderOffsets returns the archive offsets of each block header of
// every compressed member, in archive order. Stored members have no blocks
// and are skipped. Each member's packed bytes are read through the serial
// decoder, which parses the block heads; every block's symbols are decoded
// (including the last block's) so the next header, and the next member's
// decoder state, are reached from the right position. Each payload is then
// located by scanning forward in the archive.
func blockHeaderOffsets(t *testing.T, archive []byte) []int {
	t.Helper()
	var all []int
	for _, m := range blockHeaderOffsetsByMember(t, archive) {
		all = append(all, m...)
	}
	return all
}

// blockHeaderOffsetsByMember is blockHeaderOffsets grouped by compressed
// member.
func blockHeaderOffsetsByMember(t *testing.T, archive []byte) [][]int {
	t.Helper()
	r := readerFor(archive)
	defer r.Close() //nolint:errcheck
	d, win := r.dec50, r.win
	drain := make([]byte, win.size)
	var members [][]int
	from := 0
	for {
		e, err := r.NextEntry()
		if err == io.EOF {
			return members
		}
		if err != nil {
			t.Fatalf("NextEntry: %v", err)
		}
		if e.Header.Method == 0 {
			if _, err := io.Copy(io.Discard, e); err != nil {
				t.Fatal(err)
			}
			continue
		}
		var offsets []int
		for {
			if err := d.readBlockHeader(); err != nil {
				t.Fatalf("readBlockHeader: %v", err)
			}
			at := bytes.Index(archive[from:], d.payloadBuf)
			if at < 0 {
				t.Fatal("payload not found in archive")
			}
			offsets = append(offsets, from+at-blockHeaderLen(len(d.payloadBuf)))
			from += at + len(d.payloadBuf)
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
			if d.lastBlock {
				break
			}
		}
		members = append(members, offsets)
		// The member was decoded by hand, not through its Entry, so the
		// Reader would see it as short and refuse a solid successor.
		// Every block was in fact decoded and drained.
		e.remaining, e.done = 0, io.EOF
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

// testPayloadLimit is a payload limit the fixture's blocks exceed, so they
// take the oversize path.
const testPayloadLimit = 16 << 10

// A block larger than maxParallelPayload is decoded inline with the serial
// buffer, not held in a slot. Forced by lowering the limit through a test
// hook, since no fixture has a 4 MiB block.
func TestOversizeBlockIsDecodedInline(t *testing.T) {
	file := []string{filepath.Join("testdata", "rar5_solid_bench.rar")}
	serial := decodeAll(t, file, nil)
	var rd *Reader
	par := decodeAll(t, file, func(r *Reader) {
		rd = r
		r.dec50.payloadLimit = testPayloadLimit // blocks in the fixture exceed it
		r.SetWorkers(4)
	})
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
		r.dec50.payloadLimit = testPayloadLimit
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
			if data[offsets[i]]&0x80 != 0 && size > testPayloadLimit {
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
		r.dec50.payloadLimit = testPayloadLimit
		r.SetWorkers(4)
		got := readOutcomes(r)
		if len(got) == 0 || got[0].line() != serial[0].line() {
			t.Fatalf("\nserial: %s\n   par: %v", serial[0].line(), got)
		}
		noAlias(t, r)
	})
}
