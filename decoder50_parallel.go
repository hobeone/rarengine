package rarengine

import (
	"io"
	"sync"
)

const (
	maxWorkers         = 8
	maxParallelPayload = 4 << 20 // a block bigger than this is decoded inline
)

// parallelPayloadLimit is the size above which readAhead hands a block to
// the caller goroutine instead of a slot. A variable so a test can lower it.
var parallelPayloadLimit = maxParallelPayload

// decodeHook, when set, runs in a worker before it decodes a block. It
// exists so a test can hold a worker; it costs one nil check per block.
var decodeHook func()

// blockHead is a parsed block header, before its payload is read.
type blockHead struct {
	blockBytes int
	blockBits  int
	newTables  bool
	lastBlock  bool
}

// readBlockHead reads a block's header bytes: flags, checksum, the payload
// byte count. It reads nothing of the payload.
func readBlockHead(r io.Reader) (blockHead, error) {
	var temp [2]byte
	if _, err := io.ReadFull(r, temp[:]); err != nil {
		return blockHead{}, err
	}
	flags := temp[0]
	hsum := temp[1]

	bytecount := (flags>>3)&3 + 1
	if bytecount == 4 {
		return blockHead{}, ErrCorruptDecodeHeader
	}

	h := blockHead{blockBits: int(flags)&0x07 + 1}
	sum := 0x5a ^ flags
	var blockBytesBuf [3]byte
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

	jobs    chan *blockJob
	quit    chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex // guards quit, running, and the start/stop transitions
	running bool
}

func newBlockPipeline(workers int) *blockPipeline {
	r := 2 * workers
	p := &blockPipeline{
		workers: workers,
		slots:   make([]*blockJob, r),
		tables:  make([]*tableSet, r+1),
		inUse:   make([]int, r+1),
	}
	for i := range p.slots {
		p.slots[i] = &blockJob{
			items: make([]item, itemCap),
			done:  make(chan struct{}, 1),
		}
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
		}
		if d.pipe != nil {
			d.pipe.stop()
		}
		d.pipe = newBlockPipeline(workers)
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
func (d *decoder50) stopWorkers() {
	if d.pipe != nil {
		d.pipe.stop()
	}
}

// restartWorkers arms the pipeline to start goroutines again after a stop.
func (d *decoder50) restartWorkers() {
	if d.pipe != nil {
		d.pipe.restart()
	}
}

func (p *blockPipeline) disengage(d *decoder50) {
	p.drain()
	d.tables.copyFrom(p.tables[p.cur])
	p.engaged = false
}

// drain waits for every job in flight and empties the ring. After a stop, a
// job no worker picked up has nobody to complete it, so the wait also
// watches quit; that job's done channel is then replaced. A worker that
// received the job before quit may still send on the old channel, which is
// buffered and unreferenced from then on.
func (p *blockPipeline) drain() {
	for p.count > 0 {
		j := p.slots[p.head]
		if !j.waited {
			select {
			case <-j.done:
			case <-p.quitChan():
				j.done = make(chan struct{}, 1)
			}
		}
		p.pop()
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
		h, err := readBlockHead(d.r)
		if err != nil {
			p.pendingErr = err
			return
		}
		j := p.slots[(p.head+p.count)%len(p.slots)]
		oversize := h.blockBytes > parallelPayloadLimit
		// fail records a read-ahead error. A slot that was lent the serial
		// buffer must not keep it: nothing pops a job that never entered
		// the ring, and a later block read into the slot would overwrite the
		// serial buffer under a live job.
		fail := func(err error) {
			if oversize {
				j.payload = nil
			}
			p.pendingErr = err
		}
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
		j.payload = payload
		j.bits = h.blockBits
		j.lastBlock = h.lastBlock
		j.resume.Reset(j.payload, h.blockBits)
		if h.newTables {
			if err := readCodeLengthTable(&j.resume, p.codeLength[:], &p.bitlen); err != nil {
				fail(err)
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
				fail(err)
				return
			}
			p.cur = next
		}
		j.oversize = oversize
		if oversize {
			p.oversizePending = true
			p.oversizeBlocks++
		}
		p.parallelBlocks++
		j.tables = p.tables[p.cur]
		p.inUse[p.cur]++
		p.count++
		p.sawLast = h.lastBlock
		p.submit(j)
	}
}

// start launches the decode goroutines if they are not running.
func (p *blockPipeline) start() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return
	}
	if p.quit == nil {
		p.quit = make(chan struct{})
	}
	p.jobs = make(chan *blockJob, len(p.slots))
	p.running = true
	quit, jobs := p.quit, p.jobs
	for range p.workers {
		p.wg.Go(func() {
			for {
				select {
				case <-quit:
					return
				case j := <-jobs:
					if decodeHook != nil {
						decodeHook()
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
// touches neither the ring nor the window.
func (p *blockPipeline) stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	close(p.quit)
	p.running = false
	p.mu.Unlock()
	p.wg.Wait()
}

// restart arms a fresh quit channel so the next engage can start workers.
func (p *blockPipeline) restart() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return
	}
	p.quit = make(chan struct{})
}

func (p *blockPipeline) quitChan() chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.quit
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
		// Closed under us: complete the job with the closed error so wait
		// reports it without blocking.
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
	for i := range p.tables {
		if p.tables[i] == j.tables {
			p.inUse[i]--
			break
		}
	}
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
			p.pop()
			return mapInnerErr(err)
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
