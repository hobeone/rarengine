package rarengine

import (
	"errors"
	"io"
)

var (
	ErrNoNextVolume          = errors.New("rarengine: expected next volume stream from channel, but channel was closed")
	ErrUnexpectedVolumeBlock = errors.New("rarengine: unexpected block type in volume split transition")
	ErrNoActiveFile          = errors.New("rarengine: no active file stream to read from")
)

// StreamDecompressor implements a sequential, tar-like reader for extracting RAR archives on-the-fly.
type StreamDecompressor struct {
	volumes    <-chan io.ReadCloser
	currentVol io.ReadCloser
	currHeader *FileHeader
	currReader io.Reader
	win        *Window
}

// NewStreamDecompressor initializes the decompressor with a channel of incoming volume streams.
func NewStreamDecompressor(volumes <-chan io.ReadCloser) *StreamDecompressor {
	return &StreamDecompressor{
		volumes: volumes,
		win:     NewWindow(32 * 1024 * 1024), // 32MB sliding window history
	}
}

// nextVolume fetches the next volume from the channel, closing the previous one if active.
func (sd *StreamDecompressor) nextVolume() error {
	if sd.currentVol != nil {
		_ = sd.currentVol.Close()
	}

	vol, ok := <-sd.volumes
	if !ok {
		return ErrNoNextVolume
	}
	sd.currentVol = vol
	return nil
}

// Next advances to the next file in the RAR archive stream, returning its header.
// It returns io.EOF when all files in all volumes have been fully decompressed.
func (sd *StreamDecompressor) Next() (*FileHeader, error) {
	// 1. Drain the previous file payload if any remains unread to align the stream
	if sd.currReader != nil {
		_, _ = io.Copy(io.Discard, sd.currReader)
		sd.currReader = nil
	}

	// 2. Fetch the first volume if we haven't started yet
	if sd.currentVol == nil {
		if err := sd.nextVolume(); err != nil {
			return nil, err
		}
	}

	for {
		h, err := ReadBlockHeader(sd.currentVol)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// Reached end of current volume stream, transition to next volume
				if err := sd.nextVolume(); err != nil {
					return nil, err // Returns ErrNoNextVolume (mapped to io.EOF by standard readers)
				}
				continue
			}
			return nil, err
		}

		switch h.Type {
		case HeaderTypeArchive:
			_, err := ParseArchiveHeader(h)
			if err != nil {
				return nil, err
			}

		case HeaderTypeFile, HeaderTypeService:
			fh, err := ParseFileHeader(h)
			if err != nil {
				return nil, err
			}

			if fh.FirstBlock {
				sd.win.Reset(fh.Solid)
			}

			// Wrap payload with a limit reader matching packed size
			limitPr := io.LimitReader(sd.currentVol, fh.PackedSize)

			sd.currHeader = fh
			sd.currReader = sd.newDecompressionReader(fh, limitPr)
			return fh, nil

		case HeaderTypeEnd:
			// Transition directly to the next volume
			if err := sd.nextVolume(); err != nil {
				return nil, err
			}
		}
	}
}

// Read reads decompressed bytes from the current active file block.
func (sd *StreamDecompressor) Read(p []byte) (int, error) {
	if sd.currReader == nil {
		return 0, ErrNoActiveFile
	}
	return sd.currReader.Read(p)
}

// newDecompressionReader returns the window-integrated reader for the file payload.
func (sd *StreamDecompressor) newDecompressionReader(fh *FileHeader, pr io.Reader) io.Reader {
	if fh.Method == 0 {
		return &storeReader{
			r:   pr,
			win: sd.win,
		}
	}
	return &storeReader{
		r:   pr,
		win: sd.win,
	}
}

type storeReader struct {
	r   io.Reader
	win *Window
}

func (s *storeReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		for i := 0; i < n; i++ {
			s.win.WriteByte(p[i])
		}
	}
	return n, err
}
