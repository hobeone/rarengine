package rarengine

import (
	"io"
	"sync"
	"sync/atomic"
)

const (
	maxWorkers         = 8
	maxParallelPayload = 4 << 20 // a block bigger than this is decoded inline
)

// blockHead is a parsed block header, before its payload is read.
type blockHead struct {
	blockBytes int
	blockBits  int
	newTables  bool
	lastBlock  bool
}

// readBlockHead reads a block's header bytes: flags, checksum, the payload
// byte count. It reads nothing of the payload. buf is scratch owned by the
// caller: a slice passed through io.Reader escapes, so a stack-local array
// here would cost two heap allocations per block.
func readBlockHead(r io.Reader, buf *[5]byte) (blockHead, error) {
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return blockHead{}, err
	}
	flags := buf[0]
	hsum := buf[1]

	bytecount := (flags>>3)&3 + 1
	if bytecount == 4 {
		return blockHead{}, ErrCorruptDecodeHeader
	}

	h := blockHead{blockBits: int(flags)&0x07 + 1}
	sum := 0x5a ^ flags
	blockBytesBuf := buf[2:]
	if _, err := io.ReadFull(r, blockBytesBuf[:bytecount]); err != nil {
		return blockHead{}, err
	}
	for i := range bytecount {
		n := blockBytesBuf[i]
		sum ^= n
		h.blockBytes |= int(n) << (i * 8)
	}
	if sum != hsum {
		return blockHead{}, ErrCorruptDecodeHeader
	}
	h.blockBits += (h.blockBytes - 1) * 8
	h.newTables = flags&0x80 > 0
	h.lastBlock = flags&0x40 > 0
	return h, nil
}

// blockPipeline reads blocks ahead of the window into a ring of jobs and
// replays them oldest first.
type blockPipeline struct {
	workers int

	// payloadLimit is the size above which readAhead reads a block into the
	// serial buffer instead of a slot.
	payloadLimit int
	// beforeDecode, when set, runs in a worker before it decodes a block. start
	// captures it, so it must be set before the workers start. It exists so a
	// test can hold a worker; it costs one nil check per block.
	beforeDecode func()

	slots       []*blockJob // ring storage, len R = 2*workers
	head, count int         // ring: slots[head] is the oldest in flight
	idx         int         // replay position within slots[head]
	inline      bool        // slots[head] is being finished inline (partial or oversize)

	tables []*tableSet // R+1 sets
	inUse  []int       // jobs referencing tables[i]
	cur    int         // the set the next block uses unless it carries new tables

	pendingErr error // a read-ahead error, surfaced when the ring drains
	sawLast    bool  // the last block has been read ahead
	engaged    bool  // this member is being decoded through the pipeline

	// oversizePending is set while a job whose payload lives in the serial
	// buffer is in the ring; nothing is read until it is popped.
	oversizePending bool
	oversizeBlocks  int // blocks read into the serial buffer, for tests
	parallelBlocks  int // blocks submitted through the ring, for tests

	codeLength [tableSize5]byte
	bitlen     huffmanDecoder

	jobs chan *blockJob
	// quit is written only under mu (ensureQuit, restart) and read without it
	// by the traversal goroutine in submit and wait. A pointer to the channel,
	// so a renewal is one atomic store.
	quit    atomic.Pointer[chan struct{}]
	wg      *sync.WaitGroup // the current generation of goroutines
	mu      sync.Mutex      // guards quit writes, jobs, wg, running, and the start/stop transitions
	running bool
}

func newBlockPipeline(workers int) *blockPipeline {
	r := 2 * workers
	p := &blockPipeline{
		workers:      workers,
		payloadLimit: maxParallelPayload,
		slots:        make([]*blockJob, r),
		tables:       make([]*tableSet, r+1),
		inUse:        make([]int, r+1),
	}
	for i := range p.slots {
		p.slots[i] = &blockJob{done: make(chan struct{}, 1)}
	}
	for i := range p.tables {
		p.tables[i] = &tableSet{}
		p.tables[i].prewarm()
	}
	return p
}

// setPipeline chooses the decoder for the member being built: the serial
// path for workers <= 1, otherwise a pipeline of min(workers, maxWorkers)
// decode goroutines, created on first use and kept for the Reader's life.
func (d *decoder50) setPipeline(workers int) {
	if workers <= 1 {
		if d.pipe != nil && d.pipe.engaged {
			d.pipe.disengage(d)
		}
		return
	}
	workers = min(workers, maxWorkers)
	if d.pipe == nil || d.pipe.workers != workers {
		if d.pipe != nil {
			// Hand the tables the old pipeline holds back to the serial
			// decoder, so the new one is seeded from the current ones.
			if d.pipe.engaged {
				d.pipe.disengage(d)
			} else {
				d.pipe.drain()
			}
			d.pipe.stop()
		}
		p := newBlockPipeline(workers)
		p.payloadLimit = d.payloadLimit
		p.beforeDecode = d.beforeDecode
		d.pipeMu.Lock()
		d.pipe = p
		stopped := d.pipeStopped
		d.pipeMu.Unlock()
		if stopped {
			// A Close landed before this pipeline existed; honour it. start
			// refuses the fired quit, so engage starts nothing.
			p.stop()
		}
	}
	d.pipe.engage(d)
}

func (p *blockPipeline) engage(d *decoder50) {
	p.drain()
	p.head, p.count, p.idx, p.inline = 0, 0, 0, false
	p.pendingErr, p.sawLast = nil, false
	if !p.engaged {
		// Seed from the serial decoder so a member whose first block
		// carries no tables sees what the previous member left, as the
		// serial path would.
		p.cur = p.freeTableSet()
		p.tables[p.cur].copyFrom(&d.tables)
	}
	p.engaged = true
	p.start()
}

// stopWorkers ends the pipeline's goroutines. It is the one call Reader.Close
// makes into the decoder, and touches neither the window nor the ring.
// It latches the stop on the decoder, so a Close that precedes the first
// pipeline is honoured by setPipeline. The pipeline is stopped after pipeMu is
// released: stop waits for workers, and nothing here should hold the lock
// across that wait.
func (d *decoder50) stopWorkers() {
	d.pipeMu.Lock()
	d.pipeStopped = true
	p := d.pipe
	d.pipeMu.Unlock()
	if p != nil {
		p.stop()
	}
}

// restartWorkers clears the latch and arms the pipeline to start goroutines
// again after a stop.
func (d *decoder50) restartWorkers() {
	d.pipeMu.Lock()
	d.pipeStopped = false
	p := d.pipe
	d.pipeMu.Unlock()
	if p != nil {
		p.restart()
	}
}

func (p *blockPipeline) disengage(d *decoder50) {
	p.drain()
	d.tables.copyFrom(p.tables[p.cur])
	p.engaged = false
}

// drain waits for every job in flight and empties the ring. After a stop, a
// job no worker picked up has nobody to complete it, so the wait also
// watches quit. Once quit has fired, drain waits for the workers of that
// generation to exit, which settles every token they will ever send, and
// clears the slot's done channel without blocking before releasing the
// slot. The channel itself is never replaced: a worker reads it when it
// sends. restart calls it after a stop, so quit has already fired and every
// job no worker completed takes the quit branch.
func (p *blockPipeline) drain() {
	for p.count > 0 {
		j := p.slots[p.head]
		if !j.waited {
			select {
			case <-j.done:
			case <-p.quitChan():
				p.waitWorkers()
				select {
				case <-j.done:
				default:
				}
			}
		}
		p.pop()
	}
}

// waitWorkers blocks until the goroutines of the current generation have
// exited. It does not ask them to; that is quit's job.
func (p *blockPipeline) waitWorkers() {
	p.mu.Lock()
	wg := p.wg
	p.mu.Unlock()
	if wg != nil {
		wg.Wait()
	}
}

// freeTableSet returns the index of a set no in-flight job references.
// With len(slots)+1 sets and each slot referencing one, there is always
// one.
func (p *blockPipeline) freeTableSet() int {
	for i, n := range p.inUse {
		if n == 0 {
			return i
		}
	}
	panic("rarengine: no free table set") // unreachable by construction
}

// readAhead fills the ring from d.r. A read error is not returned: it is
// recorded and surfaced by fillParallel only once every block before it
// has been replayed, which is when the serial path would have met it.
func (p *blockPipeline) readAhead(d *decoder50) {
	for p.count < len(p.slots) && !p.sawLast && p.pendingErr == nil && !p.oversizePending {
		h, err := readBlockHead(d.r, &d.headBuf)
		if err != nil {
			p.pendingErr = err
			return
		}
		j := p.slots[(p.head+p.count)%len(p.slots)]
		if j.items == nil {
			j.items = make([]item, itemCap)
		}
		oversize := h.blockBytes > p.payloadLimit
		var payload []byte
		if oversize {
			// Too big to hold in a slot: read it into the serial buffer, as
			// the serial path would, and read nothing more until it is gone.
			if cap(d.payloadBuf) < h.blockBytes {
				d.payloadBuf = make([]byte, h.blockBytes)
			} else {
				d.payloadBuf = d.payloadBuf[:h.blockBytes]
			}
			payload = d.payloadBuf
		} else if cap(j.payload) < h.blockBytes {
			payload = make([]byte, h.blockBytes)
		} else {
			payload = j.payload[:h.blockBytes]
		}
		if _, err := io.ReadFull(d.r, payload); err != nil {
			p.pendingErr = err
			return
		}
		j.bits = h.blockBits
		j.lastBlock = h.lastBlock
		j.resume.Reset(payload, h.blockBits)
		if h.newTables {
			if err := readCodeLengthTable(&j.resume, p.codeLength[:], &p.bitlen); err != nil {
				p.pendingErr = err
				return
			}
			next := p.cur
			if p.inUse[p.cur] > 0 {
				next = p.freeTableSet()
			}
			if err := p.tables[next].load(p.codeLength[:]); err != nil {
				// The serial path fails this block at readBlockHeader, after
				// every earlier block was decoded. Record it like any other
				// read-ahead error; the tables that failed to load are in a
				// set no block references.
				p.pendingErr = err
				return
			}
			p.cur = next
		}
		// Assigned only once nothing can fail: a slot that was lent the
		// serial buffer must not keep it when its job never enters the
		// ring, since nothing pops such a job.
		j.payload = payload
		j.oversize = oversize
		if oversize {
			p.oversizePending = true
			p.oversizeBlocks++
		}
		p.parallelBlocks++
		j.tables = p.tables[p.cur]
		j.tablesIdx = p.cur
		p.inUse[p.cur]++
		p.count++
		p.sawLast = h.lastBlock
		p.submit(j)
	}
}

// start launches the decode goroutines if they are not running. A pipeline
// whose quit has fired starts nothing until restart renews it: submit and
// wait then report the closed Reader.
func (p *blockPipeline) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return
	}
	quit := p.ensureQuit()
	if chanClosed(quit) {
		return
	}
	p.jobs = make(chan *blockJob, len(p.slots))
	p.running = true
	jobs := p.jobs
	beforeDecode := p.beforeDecode
	wg := new(sync.WaitGroup)
	p.wg = wg
	for range p.workers {
		wg.Go(func() {
			for {
				select {
				case <-quit:
					return
				case j := <-jobs:
					// select picks at random when quit and a queued job are
					// both ready; without this a stopped worker could decode
					// every queued block before seeing quit. A job dropped
					// here is never completed, which drain and restart
					// already handle for jobs no worker took.
					if chanClosed(quit) {
						return
					}
					if beforeDecode != nil {
						beforeDecode()
					}
					decodeBlockItems(j)
					j.done <- struct{}{}
				}
			}
		})
	}
}

// stop ends the goroutines. A worker mid-block finishes that block first
// (bounded: one block), then sees quit. Safe from any goroutine; the
// traversal goroutine blocked in wait is released by the same close. It
// touches neither the ring nor the window. A stop that finds nothing running
// still fires quit (installing one if there is none), so a Close that lands
// before engage cannot be followed by workers nobody will stop; start refuses
// a fired quit and restart renews it.
func (p *blockPipeline) stop() {
	p.mu.Lock()
	p.ensureQuit()
	p.fireQuit()
	wasRunning := p.running
	p.running = false
	wg := p.wg
	p.mu.Unlock()
	if wasRunning {
		wg.Wait()
	}
}

// ensureQuit returns the quit channel, creating it if there is none. Called
// with mu held.
func (p *blockPipeline) ensureQuit() chan struct{} {
	if q := p.quitChan(); q != nil {
		return q
	}
	q := make(chan struct{})
	p.quit.Store(&q)
	return q
}

// fireQuit closes the quit channel unless there is none or it is already
// closed. Called with mu held.
func (p *blockPipeline) fireQuit() {
	if q := p.quitChan(); q != nil && !chanClosed(q) {
		close(q)
	}
}

// restart arms the pipeline for the next engage after a stop. It runs on the
// traversal goroutine, which owns the ring: it waits for the stopped
// generation to exit (bounded by one block), releases every slot still in
// flight, clearing the tokens the workers left, drops the abandoned job
// queue, and only then installs a fresh quit. A running pipeline is left
// as it is.
func (p *blockPipeline) restart() {
	// Relies on: running is false with jobs in the ring only after quit has
	// fired, so drain's quit branch cannot block.
	p.mu.Lock()
	running := p.running
	p.mu.Unlock()
	if running {
		return
	}
	p.waitWorkers()
	p.drain()
	p.mu.Lock()
	p.jobs = nil
	q := make(chan struct{})
	p.quit.Store(&q)
	p.mu.Unlock()
}

// quitChan returns the current quit channel, nil before the first start or
// stop. It does not take mu: quit is published atomically.
func (p *blockPipeline) quitChan() chan struct{} {
	if q := p.quit.Load(); q != nil {
		return *q
	}
	return nil
}

// submit hands the job to a worker.
func (p *blockPipeline) submit(j *blockJob) {
	if j.oversize {
		// Finished inline when it reaches the head, from the bit position
		// after the tables. Nothing to decode, so it is ready at once.
		j.partial = true
		j.n = 0
		j.err = nil
		j.done <- struct{}{}
		return
	}
	select {
	case p.jobs <- j:
	case <-p.quitChan():
		// Closed under us: complete the job with the closed error and no
		// items, so wait reports it without blocking and nothing stale from
		// the slot's previous block is replayed.
		j.n, j.partial = 0, false
		j.err = ErrReaderClosed
		j.done <- struct{}{}
	}
}

// wait blocks until j is decoded or the pipeline is stopped.
func (p *blockPipeline) wait(j *blockJob) error {
	if j.waited {
		return nil
	}
	select {
	case <-j.done:
		j.waited = true
		return nil
	case <-p.quitChan():
		return ErrReaderClosed
	}
}

// pop releases slots[head].
func (p *blockPipeline) pop() {
	j := p.slots[p.head]
	p.inUse[j.tablesIdx]--
	j.tables = nil
	j.waited = false
	if j.oversize {
		// The payload is the serial buffer; the slot must not keep it, or
		// a later block would be read into it.
		j.payload = nil
		j.oversize = false
		p.oversizePending = false
	}
	p.head = (p.head + 1) % len(p.slots)
	p.count--
	p.idx = 0
	p.inline = false
}

// fillParallel is fill for an engaged pipeline: stage bytes from the
// oldest block's items until the fill target is reached, reading ahead and
// handing blocks to the workers as slots free up.
func (d *decoder50) fillParallel(win *window) error {
	p := d.pipe
	target := win.fillTarget()
	for win.Available() < target {
		if p.count == 0 {
			p.readAhead(d)
			if p.count == 0 {
				if p.pendingErr != nil {
					return p.pendingErr
				}
				return io.EOF
			}
		}
		j := p.slots[p.head]
		if err := p.wait(j); err != nil {
			return err
		}
		if !p.inline {
			exhausted, err := d.replayItems(win, j, &p.idx, target)
			if err != nil {
				return err
			}
			if !exhausted {
				return nil // target reached mid-block
			}
			if j.err != nil {
				// Serial checks the target before each symbol, so it stops
				// short of the one that failed and delivers what is staged;
				// the error comes on the next call, which finds the job here
				// with its items exhausted.
				if win.Available() >= target {
					return nil
				}
				if j.err == ErrDecoderOutOfData {
					// Serial keeps the block's reader and resumes it on the
					// next fill from where the truncated symbol left it,
					// which is j.resume; finish the block inline from there.
					p.inline = true
					return j.err
				}
				err := j.err
				p.pop()
				return err
			}
			if !j.partial {
				last := j.lastBlock
				p.pop()
				if last {
					return io.EOF
				}
				p.readAhead(d)
				continue
			}
			p.inline = true
		}
		done, err := d.finishBlockInline(win, j, target)
		if err != nil {
			if !done {
				return err // out of data: the block stays at the head, d.br resumes it
			}
			p.pop()
			return err
		}
		if done {
			last := j.lastBlock
			p.pop()
			if last {
				return io.EOF
			}
			p.readAhead(d)
		}
	}
	return nil
}
