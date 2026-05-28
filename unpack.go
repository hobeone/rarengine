package rarengine

import (
	"bytes"
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

type volumeInfo struct {
	path  string
	index int
}

// SortVolumes takes a slice of volume file paths, parses their internal main
// archive headers to extract the volume number, and returns the sorted paths
// in ascending order.
func SortVolumes(paths []string) ([]string, error) {
	var vols []volumeInfo

	for _, p := range paths {
		f, err := os.Open(p) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("rarengine: sort: open %s: %w", p, err)
		}

		volIdx, err := readVolumeIndex(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("rarengine: sort: parse %s: %w", p, err)
		}

		vols = append(vols, volumeInfo{
			path:  p,
			index: volIdx,
		})
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

func readVolumeIndex(r io.Reader) (int, error) {
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return 0, err
	}
	expectedMagic := []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}
	if !bytes.Equal(magic[:], expectedMagic) {
		return 0, errors.New("invalid RAR5 magic signature")
	}

	h, err := ReadBlockHeader(r)
	if err != nil {
		return 0, err
	}

	ah, err := ParseArchiveHeader(h)
	if err != nil {
		return 0, err
	}

	if ah.VolumeNumber < 0 {
		return 0, nil
	}
	return ah.VolumeNumber, nil
}

// UnpackDir automatically discovers, sorts, opens, and extracts a set of RAR5
// archive volume files from the same directory starting at firstVolumePath.
// It returns a slice of absolute paths of all successfully extracted files.
func UnpackDir(ctx context.Context, firstVolumePath string, outputDir string, opts UnpackOptions) ([]string, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	logger.Info("rarengine: starting volume discovery", "first_volume", firstVolumePath)
	vols, err := discoverVolumes(firstVolumePath)
	if err != nil {
		return nil, fmt.Errorf("rarengine: discover volumes: %w", err)
	}
	logger.Info("rarengine: discovered volumes", "count", len(vols), "paths", vols)

	logger.Info("rarengine: sorting volumes by internal headers")
	sortedVols, err := SortVolumes(vols)
	if err != nil {
		return nil, fmt.Errorf("rarengine: sort volumes: %w", err)
	}
	logger.Info("rarengine: sorted volumes order", "paths", sortedVols)

	// Resolve canonical absolute outputDir path (handles symlinks safely)
	absOutputDir, err := filepath.EvalSymlinks(outputDir)
	if err != nil {
		absOutputDir, err = filepath.Abs(outputDir)
		if err != nil {
			return nil, fmt.Errorf("rarengine: resolve output path: %w", err)
		}
	}

	if err := os.MkdirAll(absOutputDir, 0755); err != nil { // #nosec G301
		return nil, fmt.Errorf("rarengine: create output dir: %w", err)
	}

	root, err := os.OpenRoot(absOutputDir)
	if err != nil {
		return nil, fmt.Errorf("rarengine: sandbox output dir: %w", err)
	}
	defer func() { _ = root.Close() }()

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

	sd := NewStreamDecompressor(volumesChan)
	if opts.Password != "" {
		sd.SetPassword(opts.Password)
	}

	var extractedFiles []string

	logger.Info("rarengine: starting extraction pipeline", "output_dir", absOutputDir)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := sd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrNoNextVolume) {
				break
			}
			return nil, fmt.Errorf("rarengine: read next file: %w", err)
		}

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
					return nil, fmt.Errorf("rarengine: mkdir %s: %w", destRel, err)
				}
			}
			continue
		}

		if !opts.OverwriteFiles {
			if _, statErr := root.Stat(destRel); statErr == nil {
				logger.Info("rarengine: skipping existing file", "path", destRel)
				continue
			}
		}

		if opts.OnEntry != nil {
			opts.OnEntry(header)
		}

		if err := root.MkdirAll(filepath.Dir(destRel), 0750); err != nil {
			return nil, fmt.Errorf("rarengine: mkdir parent %s: %w", filepath.Dir(destRel), err)
		}

		out, err := root.OpenFile(destRel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return nil, fmt.Errorf("rarengine: create file %s: %w", destRel, err)
		}

		n, err := io.Copy(out, sd)
		_ = out.Close()
		if err != nil {
			return nil, fmt.Errorf("rarengine: write file %s: %w", destRel, err)
		}

		mode := header.Mode() & 0666
		if mode != 0 && header.HostOS != 0 {
			_ = root.Chmod(destRel, mode)
		}

		if !opts.IgnoreUnrarDates && !header.ModificationTime.IsZero() {
			_ = root.Chtimes(destRel, header.ModificationTime, header.ModificationTime)
		}

		absPath := filepath.Join(absOutputDir, destRel)
		extractedFiles = append(extractedFiles, absPath)

		logger.Info("rarengine: extracted entry complete", "name", header.Name, "written_bytes", n)
	}

	logger.Info("rarengine: extraction pipeline complete", "extracted_count", len(extractedFiles))
	return extractedFiles, nil
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
	if !strings.Contains(firstVol, ".part") {
		return []string{firstVol}, nil
	}

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
