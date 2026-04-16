// Package cloak embeds and extracts encrypted payloads in file metadata.
//
// It uses exiftool (for images, PDFs, and general files) and ffmpeg
// (for audio/video containers) to write payloads into the Description
// metadata tag, following Jiab77's original wire format.
//
// The streaming architecture avoids ARG_MAX limits by piping data into
// tool stdin rather than passing it as CLI arguments.
package cloak

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nightcloak/pkg/cloak/native"
)

const (
	// TagLine is the sentinel written to the Comment tag to mark
	// files that contain cloak payloads.
	TagLine = "Modified by Cloak"

	// defaultTimeout for external tool execution.
	defaultTimeout = 5 * time.Minute
)

// PayloadType distinguishes how the payload is stored in the Description tag.
type PayloadType int

const (
	// PayloadString stores data with the "S:" prefix (inline string).
	PayloadString PayloadType = iota
	// PayloadFile stores data with the "N:<name>;F:" prefix (named file).
	PayloadFile
)

// HideOpts controls how a payload is embedded into a carrier file.
type HideOpts struct {
	// CarrierPath is the source media file to embed data into.
	CarrierPath string

	// OutputPath is where the modified file is written. If empty,
	// the carrier is replaced in-place (like cloak.sh's default).
	OutputPath string

	// Payload is the raw data to embed (already encrypted by the caller).
	Payload []byte

	// PayloadName is the original filename, used when Type is PayloadFile.
	PayloadName string

	// Type selects the tag format: PayloadString ("S:") or PayloadFile ("N:;F:").
	Type PayloadType

	// Password is used by native injectors to derive a sentinel for
	// payload identification. Ignored by the exiftool/ffmpeg paths.
	Password string

	// Timeout overrides the default execution timeout. Zero means default.
	Timeout time.Duration
}

// RevealResult holds the data extracted from a carrier file.
type RevealResult struct {
	// Payload is the raw embedded data.
	Payload []byte
	// PayloadName is the original filename (empty for string payloads).
	PayloadName string
	// Type indicates how the payload was stored.
	Type PayloadType
}

// ffmpegExtensions are routed to the ffmpeg code path for embedding.
var ffmpegExtensions = map[string]bool{
	".avi": true,
	".ogg": true,
}

// textExtensions use the Unicode zero-width char carrier (no external deps).
var textExtensions = map[string]bool{
	".txt": true, ".md": true,
	".html": true, ".htm": true,
	".json": true, ".xml": true, ".csv": true,
}

// Hide embeds a payload into the carrier file's metadata tags.
//
// Routing: .png, .jpg/.jpeg, .mp3, and .pdf use native Go injectors (zero
// external deps). .avi/.ogg files use ffmpeg with FFMETADATA1. All other
// files use exiftool with the streaming -@ - pattern.
func Hide(opts HideOpts) error {
	if err := validateHideOpts(opts); err != nil {
		return err
	}

	// Capture original timestamps of the carrier for forensic preservation.
	times, err := native.GetFileTimes(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("capturing timestamps: %w", err)
	}

	// Capture parent directory timestamps. Modifying/renaming files changes the directory mtime.
	parentDir := filepath.Dir(opts.CarrierPath)
	parentTimes, err := native.GetFileTimes(parentDir)
	if err != nil {
		return fmt.Errorf("capturing parent directory timestamps: %w", err)
	}

	var hideErr error
	ext := strings.ToLower(filepath.Ext(opts.CarrierPath))
	switch {
	case ext == ".png":
		hideErr = hidePNGNative(opts)
	case ext == ".jpg" || ext == ".jpeg":
		hideErr = hideJPEGExifNative(opts)
	case ext == ".mp3":
		hideErr = hideMP3Native(opts)
	case ext == ".pdf":
		hideErr = hidePDFNative(opts)
	case textExtensions[ext]:
		hideErr = hideUnicodeNative(opts)
	case ffmpegExtensions[ext]:
		hideErr = hideFF(opts)
	default:
		hideErr = hideEX(opts)
	}

	if hideErr != nil {
		return hideErr
	}

	// Restore original timestamps to the modified file (the target).
	target := opts.OutputPath
	if target == "" {
		target = opts.CarrierPath
	}
	if err := native.RestoreFileTimes(target, times); err != nil {
		return fmt.Errorf("restoring timestamps: %w", err)
	}

	// Restore parent directory timestamps to hide the evidence of file creation/renaming.
	// Non-fatal: shared directories (e.g. /tmp) may reject chtimes if the caller is not the owner.
	if err := native.RestoreFileTimes(parentDir, parentTimes); err != nil {
		fmt.Fprintf(os.Stderr, "  [~] Warning: could not restore parent directory timestamps (%s): %v\n", parentDir, err)
	}

	return nil
}
// Wipe removes the nightcloak payload from a carrier file, restoring it to
// a clean state. Timestamps are restored after the operation.
//
// Routing mirrors Hide: native paths for PNG, JPEG, MP3, PDF. Exiftool for
// everything else.
func Wipe(carrierPath, password string) error {
	if _, err := os.Stat(carrierPath); err != nil {
		return fmt.Errorf("carrier file: %w", err)
	}

	times, err := native.GetFileTimes(carrierPath)
	if err != nil {
		return fmt.Errorf("capturing timestamps: %w", err)
	}

	parentDir := filepath.Dir(carrierPath)
	parentTimes, err := native.GetFileTimes(parentDir)
	if err != nil {
		return fmt.Errorf("capturing parent directory timestamps: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(carrierPath))

	var wipeErr error
	switch {
	case ext == ".png":
		wipeErr = wipeNative(carrierPath, func(src io.Reader, dst io.Writer) error {
			return native.PNGWipe(src, dst, password)
		})
	case ext == ".jpg" || ext == ".jpeg":
		wipeErr = wipeNative(carrierPath, func(src io.Reader, dst io.Writer) error {
			return native.JPEGExifWipe(src, dst, password)
		})
	case ext == ".mp3":
		wipeErr = wipeNative(carrierPath, func(src io.Reader, dst io.Writer) error {
			return native.MP3Wipe(src, dst, password)
		})
	case ext == ".pdf":
		wipeErr = wipeNative(carrierPath, func(src io.Reader, dst io.Writer) error {
			err := native.PDFWipe(src, dst)
			if errors.Is(err, native.ErrXREFStream) || errors.Is(err, native.ErrEncryptedPDF) {
				return wipeEX(carrierPath)
			}
			return err
		})
	case textExtensions[ext]:
		wipeErr = wipeUnicodeNative(carrierPath)
	default:
		wipeErr = wipeEX(carrierPath)
	}

	if wipeErr != nil {
		return wipeErr
	}

	if err := native.RestoreFileTimes(carrierPath, times); err != nil {
		return fmt.Errorf("restoring timestamps: %w", err)
	}

	if err := native.RestoreFileTimes(parentDir, parentTimes); err != nil {
		fmt.Fprintf(os.Stderr, "  [~] Warning: could not restore parent directory timestamps (%s): %v\n", parentDir, err)
	}

	return nil
}

// wipeNative opens carrierPath, runs fn(src, dst) into a temp file, then
// atomically replaces the carrier in-place.
func wipeNative(carrierPath string, fn func(io.Reader, io.Writer) error) error {
	src, err := os.Open(carrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dir := filepath.Dir(carrierPath)
	ext := filepath.Ext(carrierPath)
	tmp, err := os.CreateTemp(dir, "nightcloak-wipe-*"+ext)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if err := fn(src, tmp); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()

	return os.Rename(tmpPath, carrierPath)
}

// wipeEX clears the Description and Comment tags via exiftool.
func wipeEX(carrierPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "exiftool",
		"-P", "-overwrite_original",
		"-description=", "-comment=",
		carrierPath,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exiftool wipe failed: %w", err)
	}
	return nil
}

// Reveal extracts the payload from a carrier file's metadata.
//
// Routing: .png, .jpg/.jpeg, .mp3, and .pdf use native Go extractors.
// All other files use exiftool.
func Reveal(carrierPath string, password string) (*RevealResult, error) {
	ext := strings.ToLower(filepath.Ext(carrierPath))
	switch {
	case ext == ".png":
		return revealPNGNative(carrierPath, password)
	case ext == ".jpg" || ext == ".jpeg":
		return revealJPEGExifNative(carrierPath, password)
	case ext == ".mp3":
		return revealMP3Native(carrierPath, password)
	case ext == ".pdf":
		return revealPDFNative(carrierPath, password)
	case textExtensions[ext]:
		return revealUnicodeNative(carrierPath)
	default:
		return revealEX(carrierPath)
	}
}

// RevealReader extracts a payload from content that is already loaded in
// memory. ext must be the lowercase file extension including the dot
// (e.g. ".jpg"). This avoids a second disk read when the caller (e.g.
// cmdGather) already holds the file bytes from a prior scan.
//
// For formats routed to exiftool the content is written to a temp file;
// native paths stream directly from a bytes.Reader.
func RevealReader(content []byte, ext, password string) (*RevealResult, error) {
	r := bytes.NewReader(content)
	switch {
	case ext == ".png":
		wirePayload, err := native.PNGExtract(r, password)
		if err != nil {
			return nil, err
		}
		return parseDescription(string(wirePayload))

	case ext == ".jpg" || ext == ".jpeg":
		wirePayload, err := native.JPEGExifExtract(r, password)
		if err != nil {
			return nil, err
		}
		return parseDescription(string(wirePayload))

	case ext == ".mp3":
		wirePayload, err := native.MP3Extract(r, password)
		if err != nil {
			return nil, err
		}
		return parseDescription(string(wirePayload))

	case ext == ".pdf":
		wirePayload, err := native.PDFExtract(r, password)
		if errors.Is(err, native.ErrXREFStream) || errors.Is(err, native.ErrEncryptedPDF) {
			return revealExFromContent(content, ext)
		}
		if err != nil {
			return nil, err
		}
		return parseDescription(string(wirePayload))

	case textExtensions[ext]:
		wirePayload, err := native.UnicodeExtract(content)
		if err != nil {
			return nil, err
		}
		return parseDescription(string(wirePayload))

	default:
		return revealExFromContent(content, ext)
	}
}

// revealExFromContent writes content to a temp file and runs exiftool on it.
// Used by RevealReader for formats not handled natively.
func revealExFromContent(content []byte, ext string) (*RevealResult, error) {
	tmp, err := os.CreateTemp("", "nightcloak-reveal-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("writing temp file: %w", err)
	}
	tmp.Close()

	return revealEX(tmpPath)
}

// ---------------------------------------------------------------------------
// native PNG path: zero external dependencies
// ---------------------------------------------------------------------------

func hidePNGNative(opts HideOpts) error {
	outputPath := resolveOutput(opts)

	// Build the wire-format payload (same N:/S: protocol as exiftool path).
	wirePayload := buildWirePayload(opts)

	src, err := os.Open(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer dst.Close()

	if err := native.PNGInject(src, dst, wirePayload, opts.Password); err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("native PNG injection: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

func revealPNGNative(carrierPath string, password string) (*RevealResult, error) {
	f, err := os.Open(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("opening carrier: %w", err)
	}
	defer f.Close()

	wirePayload, err := native.PNGExtract(f, password)
	if err != nil {
		return nil, err
	}

	return parseDescription(string(wirePayload))
}

// ---------------------------------------------------------------------------
// native JPEG path: zero external dependencies
// ---------------------------------------------------------------------------

func hideJPEGNative(opts HideOpts) error {
	outputPath := resolveOutput(opts)
	wirePayload := buildWirePayload(opts)

	src, err := os.Open(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer dst.Close()

	if err := native.JPEGInject(src, dst, wirePayload, opts.Password); err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("native JPEG injection: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

func revealJPEGNative(carrierPath string, password string) (*RevealResult, error) {
	f, err := os.Open(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("opening carrier: %w", err)
	}
	defer f.Close()

	wirePayload, err := native.JPEGExtract(f, password)
	if err != nil {
		return nil, err
	}

	return parseDescription(string(wirePayload))
}

// ---------------------------------------------------------------------------
// native MP3 path: ID3v2 TXXX injection
// ---------------------------------------------------------------------------

func hideMP3Native(opts HideOpts) error {
	outputPath := resolveOutput(opts)
	wirePayload := buildWirePayload(opts)

	src, err := os.Open(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer dst.Close()

	if err := native.MP3Inject(src, dst, wirePayload, opts.Password); err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("native MP3 injection: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

func revealMP3Native(carrierPath string, password string) (*RevealResult, error) {
	f, err := os.Open(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("opening carrier: %w", err)
	}
	defer f.Close()

	wirePayload, err := native.MP3Extract(f, password)
	if err != nil {
		return nil, err
	}

	return parseDescription(string(wirePayload))
}

// ---------------------------------------------------------------------------
// native JPEG EXIF path: stealth mode via UserComment tag
// ---------------------------------------------------------------------------

func hideJPEGExifNative(opts HideOpts) error {
	outputPath := resolveOutput(opts)
	wirePayload := buildWirePayload(opts)

	src, err := os.Open(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer dst.Close()

	if err := native.JPEGExifInject(src, dst, wirePayload, opts.Password); err != nil {
		os.Remove(outputPath)
		return fmt.Errorf("native JPEG EXIF injection: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

func revealJPEGExifNative(carrierPath string, password string) (*RevealResult, error) {
	f, err := os.Open(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("opening carrier: %w", err)
	}
	defer f.Close()

	wirePayload, err := native.JPEGExifExtract(f, password)
	if err != nil {
		return nil, err
	}

	return parseDescription(string(wirePayload))
}

// ---------------------------------------------------------------------------
// native PDF path: flat XREF purge & inject
// ---------------------------------------------------------------------------

func hidePDFNative(opts HideOpts) error {
	outputPath := resolveOutput(opts)
	wirePayload := buildWirePayload(opts)

	src, err := os.Open(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("opening carrier: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer dst.Close()

	if err := native.PDFInject(src, dst, wirePayload, opts.Password); err != nil {
		os.Remove(outputPath)
		// Fall back to exiftool for XREF streams and encrypted PDFs.
		if errors.Is(err, native.ErrXREFStream) || errors.Is(err, native.ErrEncryptedPDF) {
			return hideEX(opts)
		}
		return fmt.Errorf("native PDF injection: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

func revealPDFNative(carrierPath string, password string) (*RevealResult, error) {
	f, err := os.Open(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("opening carrier: %w", err)
	}
	defer f.Close()

	wirePayload, err := native.PDFExtract(f, password)
	if err != nil {
		// Fall back to exiftool for unsupported PDF variants.
		if errors.Is(err, native.ErrXREFStream) || errors.Is(err, native.ErrEncryptedPDF) {
			return revealEX(carrierPath)
		}
		return nil, err
	}

	return parseDescription(string(wirePayload))
}

// ---------------------------------------------------------------------------
// native text path: Unicode zero-width char injection
// ---------------------------------------------------------------------------

func hideUnicodeNative(opts HideOpts) error {
	outputPath := resolveOutput(opts)
	wirePayload := buildWirePayload(opts)

	data, err := os.ReadFile(opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("reading carrier: %w", err)
	}
	out := native.UnicodeInject(data, wirePayload)
	if err := os.WriteFile(outputPath, out, 0o644); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return replaceIfNeeded(opts, outputPath)
}

func revealUnicodeNative(carrierPath string) (*RevealResult, error) {
	data, err := os.ReadFile(carrierPath)
	if err != nil {
		return nil, fmt.Errorf("reading carrier: %w", err)
	}
	wirePayload, err := native.UnicodeExtract(data)
	if err != nil {
		return nil, err
	}
	return parseDescription(string(wirePayload))
}

func wipeUnicodeNative(carrierPath string) error {
	data, err := os.ReadFile(carrierPath)
	if err != nil {
		return fmt.Errorf("reading carrier: %w", err)
	}
	clean, err := native.UnicodeWipe(data)
	if err != nil {
		return err
	}
	return os.WriteFile(carrierPath, clean, 0o644)
}

// buildWirePayload encodes the payload into the cloak wire format
// (same N:/S: protocol used by the exiftool and ffmpeg paths).
func buildWirePayload(opts HideOpts) []byte {
	switch opts.Type {
	case PayloadFile:
		name64 := base64.StdEncoding.EncodeToString([]byte(opts.PayloadName))
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		return []byte(fmt.Sprintf("N:%s;F:%s", name64, payload64))
	case PayloadString:
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		return []byte(fmt.Sprintf("S:%s", payload64))
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// exiftool path: streaming via -@ -
// ---------------------------------------------------------------------------

// hideEX writes tags to exiftool's stdin using the -@ - flag.
//
// The pipe goroutine writes two lines:
//
//	-comment=Modified by Cloak
//	-description=N:<b64name>;F:<payload>    (or S:<payload>)
//
// exiftool reads these as if they were CLI arguments, but from stdin
// there is no ARG_MAX limit on the payload size.
func hideEX(opts HideOpts) error {
	ctx, cancel := contextWithTimeout(opts.Timeout)
	defer cancel()

	outputPath := resolveOutput(opts)
	args := []string{"-P", "-@", "-", "-o", outputPath, opts.CarrierPath}

	cmd := exec.CommandContext(ctx, "exiftool", args...)
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	// Start exiftool before writing to stdin.
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting exiftool: %w", err)
	}

	// Goroutine streams tag arguments into exiftool's stdin.
	writeErr := make(chan error, 1)
	go func() {
		defer stdin.Close()
		writeErr <- writeExifTags(stdin, opts)
	}()

	// Wait for both the writer goroutine and the process.
	if err := <-writeErr; err != nil {
		// Kill the process if the writer failed.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("writing tags: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("exiftool failed: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

// writeExifTags streams tag arguments into the writer (exiftool's stdin).
func writeExifTags(w io.Writer, opts HideOpts) error {
	// Line 1: sentinel comment tag.
	if _, err := fmt.Fprintf(w, "-comment=%s\n", TagLine); err != nil {
		return err
	}

	// Line 2: description tag with payload.
	switch opts.Type {
	case PayloadFile:
		name64 := base64.StdEncoding.EncodeToString([]byte(opts.PayloadName))
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		_, err := fmt.Fprintf(w, "-description=N:%s;F:%s\n", name64, payload64)
		return err

	case PayloadString:
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		_, err := fmt.Fprintf(w, "-description=S:%s\n", payload64)
		return err

	default:
		return fmt.Errorf("unknown payload type: %d", opts.Type)
	}
}

// revealEX reads metadata from exiftool's JSON output and parses the
// cloak protocol from the Description tag.
func revealEX(carrierPath string) (*RevealResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "exiftool", "-P", "-json", carrierPath)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exiftool failed: %w", err)
	}

	return parseExifJSON(stdout.Bytes())
}

// parseExifJSON extracts cloak data from exiftool's JSON output.
//
// exiftool -json outputs an array: [{"Comment":"...", "Description":"...", ...}]
func parseExifJSON(data []byte) (*RevealResult, error) {
	var tags []map[string]interface{}
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, fmt.Errorf("parsing exiftool JSON: %w", err)
	}
	if len(tags) == 0 {
		return nil, errors.New("exiftool returned no tags")
	}

	entry := tags[0]

	// Check the sentinel Comment tag (may be absent for PDFs).
	comment, _ := entry["Comment"].(string)
	desc, _ := entry["Description"].(string)

	if comment != TagLine && desc == "" {
		return nil, errors.New("no cloak payload found in file")
	}

	return parseDescription(desc)
}

// parseDescription decodes the cloak wire format from the Description tag.
//
// Formats:
//
//	"N:<base64_name>;F:<base64_payload>"  → PayloadFile
//	"S:<base64_payload>"                  → PayloadString
func parseDescription(desc string) (*RevealResult, error) {
	if desc == "" {
		return nil, errors.New("empty description tag")
	}

	// Detect type prefix.
	if strings.HasPrefix(desc, "N:") {
		return parseFilePayload(desc)
	}
	if strings.HasPrefix(desc, "S:") {
		return parseStringPayload(desc)
	}

	return nil, fmt.Errorf("unrecognized description format: %.40s...", desc)
}

// parseFilePayload handles "N:<base64_name>;F:<base64_payload>".
func parseFilePayload(desc string) (*RevealResult, error) {
	// Split on ";" to separate name and file data.
	parts := strings.SplitN(desc, ";", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed file payload: missing ';' separator")
	}

	// Extract name: "N:<base64>" → strip "N:" prefix.
	nameB64 := strings.TrimPrefix(parts[0], "N:")
	nameBytes, err := base64.StdEncoding.DecodeString(nameB64)
	if err != nil {
		return nil, fmt.Errorf("decoding payload name: %w", err)
	}

	// Extract data: "F:<base64>" → strip "F:" prefix.
	if !strings.HasPrefix(parts[1], "F:") {
		return nil, errors.New("malformed file payload: missing 'F:' prefix")
	}
	dataB64 := strings.TrimPrefix(parts[1], "F:")
	payload, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("decoding payload data: %w", err)
	}

	return &RevealResult{
		Payload:     payload,
		PayloadName: string(nameBytes),
		Type:        PayloadFile,
	}, nil
}

// parseStringPayload handles "S:<base64_payload>".
func parseStringPayload(desc string) (*RevealResult, error) {
	dataB64 := strings.TrimPrefix(desc, "S:")
	payload, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, fmt.Errorf("decoding string payload: %w", err)
	}

	return &RevealResult{
		Payload: payload,
		Type:    PayloadString,
	}, nil
}

// ---------------------------------------------------------------------------
// ffmpeg path: FFMETADATA1 temp file
// ---------------------------------------------------------------------------

// hideFF writes metadata using ffmpeg's FFMETADATA1 input format.
//
// Unlike exiftool, ffmpeg requires the metadata as a file input (-i).
// We write the metadata to a temp file, pass it as the second -i,
// and remove it immediately after ffmpeg finishes.
func hideFF(opts HideOpts) error {
	ctx, cancel := contextWithTimeout(opts.Timeout)
	defer cancel()

	outputPath := resolveOutput(opts)

	// Detect the container format for the -f flag.
	format, err := probeFormat(ctx, opts.CarrierPath)
	if err != nil {
		return fmt.Errorf("probing format: %w", err)
	}

	// Write FFMETADATA1 to a temp file.
	metaFile, err := writeFFMetadata(opts)
	if err != nil {
		return err
	}
	defer os.Remove(metaFile)

	args := []string{
		"-hide_banner", "-y",
		"-i", opts.CarrierPath,
		"-i", metaFile,
		"-c", "copy",
		"-movflags", "use_metadata_tags",
		"-map_metadata", "0",
		"-map_metadata", "1",
		"-f", format,
		outputPath,
	}

	cmd := exec.CommandContext(ctx, "ffmpeg", args...)
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ffmpeg failed: %w", err)
	}

	return replaceIfNeeded(opts, outputPath)
}

// probeFormat uses ffprobe to detect the container format name.
func probeFormat(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, "ffprobe",
		"-loglevel", "error",
		"-show_format",
		"-of", "json",
		path,
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ffprobe failed: %w", err)
	}

	var result struct {
		Format struct {
			FormatName string `json:"format_name"`
		} `json:"format"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return "", fmt.Errorf("parsing ffprobe JSON: %w", err)
	}

	if result.Format.FormatName == "" {
		return "", errors.New("ffprobe returned empty format name")
	}

	return result.Format.FormatName, nil
}

// writeFFMetadata writes the FFMETADATA1 content to a temp file
// and returns the file path.
func writeFFMetadata(opts HideOpts) (string, error) {
	f, err := os.CreateTemp("", "nightcloak-meta-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating temp metadata file: %w", err)
	}
	defer f.Close()

	// FFMETADATA1 header (the leading ";" is required by the format).
	if _, err := fmt.Fprintf(f, ";FFMETADATA1\n"); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(f, "comment=%s\n", TagLine); err != nil {
		return "", err
	}

	switch opts.Type {
	case PayloadFile:
		name64 := base64.StdEncoding.EncodeToString([]byte(opts.PayloadName))
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		_, err = fmt.Fprintf(f, "description=N:%s;F:%s\n", name64, payload64)

	case PayloadString:
		payload64 := base64.StdEncoding.EncodeToString(opts.Payload)
		_, err = fmt.Fprintf(f, "description=S:%s\n", payload64)

	default:
		err = fmt.Errorf("unknown payload type: %d", opts.Type)
	}

	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

// ---------------------------------------------------------------------------
// inspect: read and display file metadata tags
// ---------------------------------------------------------------------------

// Inspect reads all metadata tags from a file using exiftool and returns
// the raw JSON output. Equivalent to cloak.sh's no-arg mode (get_tags).
func Inspect(carrierPath string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "exiftool", "-P", "-json", carrierPath)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("exiftool failed: %w", err)
	}

	// Pretty-print the JSON.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, stdout.Bytes(), "", "  "); err != nil {
		return stdout.Bytes(), nil // fallback to raw
	}
	return pretty.Bytes(), nil
}

// ---------------------------------------------------------------------------
// folder compression: zip in-memory
// ---------------------------------------------------------------------------

// ZipFolder compresses a directory into a zip archive in memory and returns
// the archive bytes along with the archive name. Equivalent to cloak.sh's
// cmp_folder() which uses zip -r.
func ZipFolder(dirPath string) ([]byte, string, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, "", fmt.Errorf("stat folder: %w", err)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("not a directory: %s", dirPath)
	}

	archiveName := filepath.Base(dirPath) + ".zip"

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	err = filepath.Walk(dirPath, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Build the relative path inside the zip (matching cloak.sh's "cd $dir && zip -r . ")
		rel, err := filepath.Rel(dirPath, path)
		if err != nil {
			return err
		}

		// Create zip header from file info.
		header, err := zip.FileInfoHeader(fi)
		if err != nil {
			return err
		}
		header.Name = rel
		if fi.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}

		if fi.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(w, f)
		return err
	})

	if err != nil {
		return nil, "", fmt.Errorf("zipping folder: %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("closing zip: %w", err)
	}

	return buf.Bytes(), archiveName, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func validateHideOpts(opts HideOpts) error {
	if opts.CarrierPath == "" {
		return errors.New("carrier path is required")
	}
	if _, err := os.Stat(opts.CarrierPath); err != nil {
		return fmt.Errorf("carrier file: %w", err)
	}
	if len(opts.Payload) == 0 {
		return errors.New("payload is empty")
	}
	if opts.Type == PayloadFile && opts.PayloadName == "" {
		return errors.New("payload name is required for file payloads")
	}
	return nil
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	if d == 0 {
		d = defaultTimeout
	}
	return context.WithTimeout(context.Background(), d)
}

// resolveOutput determines the output file path. If OutputPath is not
// set, we write to a temp .mod file alongside the carrier (matching
// cloak.sh's behavior of carrier.mod.ext).
func resolveOutput(opts HideOpts) string {
	if opts.OutputPath != "" {
		return opts.OutputPath
	}
	dir := filepath.Dir(opts.CarrierPath)
	name := filepath.Base(opts.CarrierPath)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return filepath.Join(dir, stem+".mod"+ext)
}

// replaceIfNeeded moves the .mod output over the original carrier
// when no explicit OutputPath was set (in-place replacement).
func replaceIfNeeded(opts HideOpts, outputPath string) error {
	if opts.OutputPath != "" {
		// Explicit output path — don't replace the original.
		return nil
	}
	return os.Rename(outputPath, opts.CarrierPath)
}
