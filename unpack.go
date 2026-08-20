package rarengine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// UnpackOptions configures the high-level archive extraction process.
type UnpackOptions struct {
	Password         string
	Logger           *slog.Logger
	OneFolder        bool
	OverwriteFiles   bool
	IgnoreUnrarDates bool
	OnEntry          func(header *FileHeader)
}

// UnpackResult reports what an extraction produced. Damage is a result rather
// than an error: one member a RAR archive cannot deliver says nothing about
// the members behind it, and in a non-solid archive those are independently
// readable. Returning only an error forced the caller to discard them.
//
// A non-nil error from UnpackDir is archive-level -- the volumes could not be
// opened, or the stream stopped being parseable. The result is still returned
// alongside it, so an abort partway through reports what it managed first.
type UnpackResult struct {
	// Files holds the absolute path of every member written to disk.
	Files []string

	// Damaged holds one entry per member that could not be delivered. Empty
	// on a clean archive. A caller reporting success without consulting it
	// is claiming more than the extraction proved.
	Damaged []DamagedEntry
}

// DamagedEntry identifies one member that could not be extracted, and why.
// Nothing was left on disk for it: a partially written file is removed before
// the entry is recorded, because a truncated file is indistinguishable from a
// complete one once extraction has finished.
type DamagedEntry struct {
	// Header is the failed member's header, carried over from FileError.
	// Never nil -- an error that cannot name its member is not damage this
	// type can describe, and stays an archive-level error instead.
	Header *FileHeader

	// Err is the underlying cause: ErrTruncatedFile, ErrCRCMismatch, or
	// whichever sentinel the decode failed with. Match it with errors.Is.
	Err error
}

// asDamaged reports whether err is a per-member failure that leaves the stream
// standing on the next block header, and converts it if so.
//
// The *FileError type is the whole test. It is constructed in exactly one
// place, gated on proof that the failed member's packed remainder was read
// down to zero, so its presence -- and nothing else about the error -- is what
// makes continuing to the next member safe. Widening this to any other error
// would resume parsing at an offset the block structure does not describe.
func asDamaged(err error) (DamagedEntry, bool) {
	fe, ok := errors.AsType[*FileError](err)
	if !ok || fe.Header == nil {
		return DamagedEntry{}, false
	}
	return DamagedEntry{Header: fe.Header, Err: fe.Err}, true
}

type volumeInfo struct {
	path  string
	index int
}

// SortVolumes takes a slice of volume file paths, parses their internal main
// archive headers to extract the volume number, and returns the sorted paths
// in ascending order.
func SortVolumes(paths []string) ([]string, error) {
	var vols []volumeInfo
	var parseFailed bool

	for _, p := range paths {
		if idx, ok := getClassicVolumeIndex(p); ok {
			vols = append(vols, volumeInfo{
				path:  p,
				index: idx,
			})
			continue
		}

		f, err := os.Open(p) // #nosec G304
		if err != nil {
			parseFailed = true
			break
		}

		volIdx, err := readVolumeIndex(f)
		_ = f.Close()
		if err != nil {
			parseFailed = true
			break
		}

		vols = append(vols, volumeInfo{
			path:  p,
			index: volIdx,
		})
	}

	if parseFailed {
		sorted := append([]string(nil), paths...)
		slices.Sort(sorted)
		return sorted, nil
	}

	slices.SortFunc(vols, func(a, b volumeInfo) int {
		return cmp.Compare(a.index, b.index)
	})

	sorted := make([]string, len(vols))
	for i, v := range vols {
		sorted[i] = v.path
	}
	return sorted, nil
}

func getClassicVolumeIndex(path string) (int, bool) {
	if strings.Contains(strings.ToLower(path), ".part") {
		return -1, false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".rar" {
		return 0, true
	}
	if len(ext) == 4 && ext[1] == 'r' && ext[2] >= '0' && ext[2] <= '9' && ext[3] >= '0' && ext[3] <= '9' {
		var idx int
		_, _ = fmt.Sscanf(ext[2:], "%d", &idx)
		return idx + 1, true
	}
	return -1, false
}

func readVolumeIndex(r io.Reader) (int, error) {
	version, err := detectVersion(r)
	if err != nil {
		return 0, err
	}

	var h *BlockHeader
	switch version {
	case VersionRAR5:
		h, err = ReadBlockHeader(r)
	case VersionRAR3:
		h, err = ReadRAR3BlockHeader(r)
	default:
		return 0, fmt.Errorf("unsupported RAR version: %v", version)
	}

	if err != nil {
		return 0, err
	}

	if version == VersionRAR5 {
		ah, err := ParseArchiveHeader(h)
		if err != nil {
			return 0, err
		}
		if ah.VolumeNumber < 0 {
			return 0, nil
		}
		return ah.VolumeNumber, nil
	} else {
		if h.Type != 0x73 {
			return 0, errors.New("invalid archive header type")
		}
		return 0, nil
	}
}

// UnpackDir automatically discovers, sorts, opens, and extracts a set of RAR5
// archive volume files from the same directory starting at firstVolumePath.
// It returns a slice of absolute paths of all successfully extracted files.
// setupSandbox prepares the target output directory and opens a sandboxed os.Root jail.
func setupSandbox(outputDir string) (*os.Root, string, error) {
	// Resolve canonical absolute outputDir path (handles symlinks safely)
	absOutputDir, err := filepath.EvalSymlinks(outputDir)
	if err != nil {
		absOutputDir, err = filepath.Abs(outputDir)
		if err != nil {
			return nil, "", fmt.Errorf("rarengine: resolve output path: %w", err)
		}
	}

	if err := os.MkdirAll(absOutputDir, 0755); err != nil { // #nosec G301
		return nil, "", fmt.Errorf("rarengine: create output dir: %w", err)
	}

	root, err := os.OpenRoot(absOutputDir)
	if err != nil {
		return nil, "", fmt.Errorf("rarengine: sandbox output dir: %w", err)
	}
	return root, absOutputDir, nil
}

// openVolumeChannel opens volume file handles sequentially and pushes them to a buffered channel.
func openVolumeChannel(sortedVols []string) (chan io.ReadCloser, error) {
	volumesChan := make(chan io.ReadCloser, len(sortedVols))
	for _, volPath := range sortedVols {
		vf, err := os.Open(volPath) // #nosec G304
		if err != nil {
			close(volumesChan)
			for v := range volumesChan {
				_ = v.Close()
			}
			return nil, fmt.Errorf("rarengine: open volume %s: %w", volPath, err)
		}
		volumesChan <- vf
	}
	close(volumesChan)
	return volumesChan, nil
}

// extractEntry extracts a single decompressed entry into the sandboxed root.
// extractEntry writes one member to disk.
//
// It reports a decode failure separately from a filesystem failure, because
// only the first is survivable. A *FileError is never available here: it is
// built in endFile, which Next drives, so a failing read returns the bare
// cause and the caller must supply the header itself.
func extractEntry(ctx context.Context, root *os.Root, sd *StreamDecompressor, header *FileHeader, opts UnpackOptions, absOutputDir string, logger *slog.Logger) (path string, streamErr error, err error) {
	var destRel string
	if opts.OneFolder {
		destRel = filepath.Base(header.Name)
	} else {
		destRel = header.Name
	}

	if opts.OneFolder && !opts.OverwriteFiles {
		destRel = uniquePath(root, destRel)
	}

	// Convert slashes to host-native separators for relative path (needed for Windows)
	destRel = filepath.FromSlash(destRel)

	logger.Info("rarengine: extracting entry", "name", header.Name, "target_rel", destRel, "size", header.UnpackedSize, "is_dir", header.IsDir)

	if header.IsDir {
		if !opts.OneFolder {
			if err := root.MkdirAll(destRel, 0750); err != nil {
				return "", nil, fmt.Errorf("rarengine: mkdir %s: %w", destRel, err)
			}
		}
		return "", nil, nil
	}

	if !opts.OverwriteFiles {
		if _, statErr := root.Stat(destRel); statErr == nil {
			logger.Info("rarengine: skipping existing file", "path", destRel)
			return "", nil, nil
		}
	}

	if opts.OnEntry != nil {
		opts.OnEntry(header)
	}

	if err := root.MkdirAll(filepath.Dir(destRel), 0750); err != nil {
		return "", nil, fmt.Errorf("rarengine: mkdir parent %s: %w", filepath.Dir(destRel), err)
	}

	out, err := root.OpenFile(destRel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", nil, fmt.Errorf("rarengine: create file %s: %w", destRel, err)
	}

	n, err := io.Copy(out, &contextReader{ctx: ctx, r: sd})
	_ = out.Close()
	if err != nil {
		// The file was created and partially written before the failure, and
		// this function reports no path for it, so leaving it behind puts a
		// truncated file in the output directory that the result never
		// mentions. Removing it is what keeps "damaged" and "extracted"
		// disjoint on disk as well as in UnpackResult.
		if rmErr := root.Remove(destRel); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			logger.Warn("rarengine: could not remove partial file", "path", destRel, "err", rmErr)
		}
		// Cancellation is not damage -- the member may have been perfectly
		// intact and the caller simply stopped. Reporting it as a damaged
		// entry would put a fabricated failure in the result and blame the
		// archive for the caller's own decision.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", nil, ctxErr
		}
		return "", err, nil
	}

	mode := header.Mode() & 0666
	if mode != 0 && header.HostOS != 0 {
		_ = root.Chmod(destRel, mode)
	}

	if !opts.IgnoreUnrarDates && !header.ModificationTime.IsZero() {
		_ = root.Chtimes(destRel, header.ModificationTime, header.ModificationTime)
	}

	absPath := filepath.Join(absOutputDir, destRel)
	logger.Info("rarengine: extracted entry complete", "name", header.Name, "written_bytes", n)
	return absPath, nil, nil
}

// UnpackDir extracts a RAR archive sequentially from the first volume path
// into the output directory.
//
// A member that cannot be delivered -- it ended short, or failed its checksum
// -- does not stop the extraction. It is recorded in UnpackResult.Damaged and
// traversal continues, because in a non-solid archive the members behind it
// are independently readable. Nothing is written to disk for such a member.
//
// A solid archive is different: its members back-reference their predecessors'
// decoded bytes, so once one is damaged the rest cannot be reconstructed.
// Those are refused with ErrSolidStreamBroken, which is returned as the
// error, along with the result accumulated up to that point.
func UnpackDir(ctx context.Context, firstVolumePath string, outputDir string, opts UnpackOptions) (UnpackResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if err := ctx.Err(); err != nil {
		return UnpackResult{}, err
	}

	logger.Info("rarengine: starting volume discovery", "first_volume", firstVolumePath)
	vols, err := discoverVolumes(firstVolumePath)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("rarengine: discover volumes: %w", err)
	}
	logger.Info("rarengine: discovered volumes", "count", len(vols), "paths", vols)

	logger.Info("rarengine: sorting volumes by internal headers")
	sortedVols, err := SortVolumes(vols)
	if err != nil {
		return UnpackResult{}, fmt.Errorf("rarengine: sort volumes: %w", err)
	}
	logger.Info("rarengine: sorted volumes order", "paths", sortedVols)

	root, absOutputDir, err := setupSandbox(outputDir)
	if err != nil {
		return UnpackResult{}, err
	}
	defer func() { _ = root.Close() }()

	volumesChan, err := openVolumeChannel(sortedVols)
	if err != nil {
		return UnpackResult{}, err
	}

	sd := NewStreamDecompressor(volumesChan)
	if opts.Password != "" {
		sd.SetPassword(opts.Password)
	}

	var res UnpackResult

	// recorded tracks whether the member currently in progress has already
	// been added to res.Damaged by the read site below, so that the FileError
	// Next reports for that same member is not counted twice.
	recorded := false

	// Every exit below returns res, not a zero value. An archive-level failure
	// partway through still extracted whatever came before it, and discarding
	// that is the behaviour this reporting exists to remove.
	logger.Info("rarengine: starting extraction pipeline", "output_dir", absOutputDir)
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		header, err := sd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				break
			}
			// Damage reaches this site for a member that was never read --
			// a directory entry, or a file skipped because it already
			// existed -- which Next drains on the caller's behalf. A member
			// that WAS read has already been recorded below and arrives
			// here only carrying its verdict; see recorded.
			if d, ok := asDamaged(err); ok {
				// A file whose read already failed reaches here a second time,
				// now carrying its verdict. Recording it again would report
				// one damaged member as two.
				if !recorded {
					logger.Warn("rarengine: skipping damaged entry", "name", d.Header.Name, "err", d.Err)
					res.Damaged = append(res.Damaged, d)
				}
				recorded = false
				continue
			}
			return res, fmt.Errorf("rarengine: read next file: %w", err)
		}
		recorded = false

		filePath, streamErr, err := extractEntry(ctx, root, sd, header, opts, absOutputDir, logger)
		if err != nil {
			return res, err
		}
		if streamErr != nil {
			// Recorded here rather than from the FileError below because the
			// two sites see different things. A file that reached its
			// declared size and then failed its CRC32 surfaces the mismatch
			// during the read and Next afterwards returns the NEXT header
			// cleanly, so waiting for a FileError would drop that member from
			// both Files and Damaged and report the archive as fully
			// extracted. The header needed to describe it is already in hand.
			logger.Warn("rarengine: skipping damaged entry", "name", header.Name, "err", streamErr)
			res.Damaged = append(res.Damaged, DamagedEntry{Header: header, Err: streamErr})
			recorded = true
			continue
		}
		if filePath != "" {
			res.Files = append(res.Files, filePath)
		}
	}

	logger.Info("rarengine: extraction pipeline complete",
		"extracted_count", len(res.Files), "damaged_count", len(res.Damaged))
	return res, nil
}

func uniquePath(root *os.Root, destRel string) string {
	if _, err := root.Stat(destRel); err != nil {
		return destRel // doesn't exist, use as-is
	}

	dir := filepath.Dir(destRel)
	base := filepath.Base(destRel)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	for i := 1; i < 10000; i++ {
		var candidate string
		if dir == "." {
			candidate = fmt.Sprintf("%s_%d%s", name, i, ext)
		} else {
			candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", name, i, ext))
		}
		if _, err := root.Stat(candidate); err != nil {
			return candidate
		}
	}

	return destRel
}

func discoverVolumes(firstVol string) ([]string, error) {
	if strings.Contains(firstVol, ".part") {
		return discoverPartVolumes(firstVol)
	}

	ext := strings.ToLower(filepath.Ext(firstVol))
	if ext == ".rar" || (len(ext) == 4 && ext[1] == 'r' && ext[2] >= '0' && ext[2] <= '9' && ext[3] >= '0' && ext[3] <= '9') {
		return discoverClassicVolumes(firstVol)
	}

	return []string{firstVol}, nil
}

func discoverPartVolumes(firstVol string) ([]string, error) {
	idx := strings.Index(firstVol, ".part")
	if idx == -1 {
		return []string{firstVol}, nil
	}
	prefix := firstVol[:idx+5]
	remaining := firstVol[idx+5:]

	var numStr strings.Builder
	var suffix string
	for i, c := range remaining {
		if c >= '0' && c <= '9' {
			numStr.WriteString(string(c))
		} else {
			suffix = remaining[i:]
			break
		}
	}

	if numStr.String() == "" {
		return []string{firstVol}, nil
	}

	isZeroPadded := len(numStr.String()) > 1 && numStr.String()[0] == '0'

	var volumes []string
	partNum := 1
	for {
		var volPath string
		if isZeroPadded {
			volPath = fmt.Sprintf("%s%0*d%s", prefix, len(numStr.String()), partNum, suffix)
		} else {
			volPath = fmt.Sprintf("%s%d%s", prefix, partNum, suffix)
		}

		if _, err := os.Stat(volPath); err != nil {
			if os.IsNotExist(err) {
				if partNum > 1 {
					break
				}
				volPath = firstVol
				if _, err := os.Stat(volPath); err == nil {
					volumes = append(volumes, volPath)
				}
				break
			}
			return nil, err
		}
		volumes = append(volumes, volPath)
		partNum++
	}

	return volumes, nil
}

func discoverClassicVolumes(firstVol string) ([]string, error) {
	ext := filepath.Ext(firstVol)
	prefix := firstVol[:len(firstVol)-len(ext)]

	var volumes []string

	// Check if archive.rar exists
	rarPath := prefix + ".rar"
	if _, err := os.Stat(rarPath); err == nil {
		volumes = append(volumes, rarPath)
	}

	// Scan from .r00 up to .r99 contiguous sequence
	for i := range 100 {
		volPath := fmt.Sprintf("%s.r%02d", prefix, i)
		if _, err := os.Stat(volPath); err == nil {
			alreadyAdded := slices.Contains(volumes, volPath)
			if !alreadyAdded {
				volumes = append(volumes, volPath)
			}
		} else if os.IsNotExist(err) {
			if i > 0 || len(volumes) > 0 {
				break
			}
		} else {
			return nil, err
		}
	}

	if len(volumes) == 0 {
		if _, err := os.Stat(firstVol); err == nil {
			return []string{firstVol}, nil
		}
	}
	return volumes, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *contextReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}
