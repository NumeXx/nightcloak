package native

/*
Polyglot carrier embedding.

A polyglot file is simultaneously a valid JPEG/PNG/PDF and a valid ZIP archive.
Format parsers (JPEG/PNG/PDF) stop at their respective end-of-content markers;
ZIP readers scan backward from the file end for the End of Central Directory
(EOCD) record.

Wire layout:
  [carrier bytes trimmed to natural end] [ZIP archive]

The ZIP contains exactly one entry named "data" holding the encrypted payload,
stored uncompressed (STORE method — payload is already encrypted, incompressible).

Offset patching: when carrier bytes are prepended to a standalone ZIP, the
ZIP's internal offsets (EOCD central-directory pointer and each central-directory
entry's local-header pointer) are wrong by exactly len(carrier). shiftZIPOffsets
fixes them in one pass before the bytes are written.
*/

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	pngSignatureBytes = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	iendChunkType     = []byte{'I', 'E', 'N', 'D'}
)

const (
	zipLFHSig  = uint32(0x04034b50) // local file header
	zipCDSig   = uint32(0x02014b50) // central directory
	zipEOCDSig = uint32(0x06054b50) // end of central directory
)

/*
PolyHide appends payload as a ZIP archive to carrier, creating a polyglot file
that is simultaneously a valid JPEG/PNG/PDF and a valid ZIP.

ext must be one of ".jpg", ".jpeg", ".png", ".pdf" (case-insensitive).
*/
func PolyHide(carrier, payload []byte, ext string) ([]byte, error) {
	trimmed, err := trimCarrier(carrier, ext)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fh := &zip.FileHeader{Name: "data", Method: zip.Store}
	fw, err := w.CreateHeader(fh)
	if err != nil {
		return nil, fmt.Errorf("creating zip entry: %w", err)
	}
	if _, err := fw.Write(payload); err != nil {
		return nil, fmt.Errorf("writing zip entry: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing zip: %w", err)
	}

	zipData, err := shiftZIPOffsets(buf.Bytes(), uint32(len(trimmed)))
	if err != nil {
		return nil, fmt.Errorf("patching zip offsets: %w", err)
	}

	return append(trimmed, zipData...), nil
}

/* PolyReveal extracts and returns the payload from a polyglot file created by PolyHide.
Does not require knowing the carrier type — reads the ZIP trailer directly. */
func PolyReveal(data []byte) ([]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a polyglot or ZIP corrupt: %w", err)
	}
	for _, f := range r.File {
		if f.Name == "data" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening zip entry: %w", err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, errors.New("data entry not found in ZIP")
}

/* PolyWipe strips the appended ZIP from a polyglot, returning the original carrier bytes.
Detects carrier format from magic bytes — no extension argument required. */
func PolyWipe(data []byte) ([]byte, error) {
	ext, err := detectPolyFormat(data)
	if err != nil {
		return nil, err
	}
	return trimCarrier(data, ext)
}

// ---------------------------------------------------------------------------
// carrier trimming — find natural end of each format
// ---------------------------------------------------------------------------

func trimCarrier(data []byte, ext string) ([]byte, error) {
	switch strings.ToLower(ext) {
	case ".jpg", ".jpeg":
		return trimJPEG(data)
	case ".png":
		return trimPNG(data)
	case ".pdf":
		return trimPDF(data)
	default:
		return nil, fmt.Errorf("unsupported carrier type %q: must be .jpg/.jpeg/.png/.pdf", ext)
	}
}

func trimJPEG(data []byte) ([]byte, error) {
	// Scan backward for last FF D9 (EOI marker).
	for i := len(data) - 2; i >= 0; i-- {
		if data[i] == 0xFF && data[i+1] == 0xD9 {
			return data[:i+2], nil
		}
	}
	return nil, errors.New("JPEG EOI marker (FF D9) not found")
}

func trimPNG(data []byte) ([]byte, error) {
	// IEND chunk layout: 4B length (0) + 4B type ("IEND") + 0B data + 4B CRC = 12 bytes.
	// Scan backward for IEND chunk type bytes.
	for i := len(data) - 12; i >= 8; i-- {
		if bytes.Equal(data[i+4:i+8], iendChunkType) {
			return data[:i+12], nil
		}
	}
	return nil, errors.New("PNG IEND chunk not found")
}

func trimPDF(data []byte) ([]byte, error) {
	marker := []byte("%%EOF")
	idx := bytes.LastIndex(data, marker)
	if idx < 0 {
		return nil, errors.New("PDF %%EOF marker not found")
	}
	end := idx + len(marker)
	// Consume trailing CR/LF after %%EOF (spec allows one line terminator).
	for end < len(data) && (data[end] == '\r' || data[end] == '\n') {
		end++
	}
	return data[:end], nil
}

func detectPolyFormat(data []byte) (string, error) {
	if len(data) < 8 {
		return "", errors.New("file too short to detect format")
	}
	if data[0] == 0xFF && data[1] == 0xD8 {
		return ".jpg", nil
	}
	if bytes.HasPrefix(data, pngSignatureBytes) {
		return ".png", nil
	}
	if bytes.HasPrefix(data, []byte("%PDF")) {
		return ".pdf", nil
	}
	return "", errors.New("unsupported format: not JPEG, PNG, or PDF")
}

// ---------------------------------------------------------------------------
// ZIP offset patching
// ---------------------------------------------------------------------------

/*
shiftZIPOffsets patches a standalone ZIP's internal offsets by delta bytes.

Required when prepending carrier bytes: the EOCD central-directory offset
and each central-directory entry's local-header offset must be increased by
len(carrier) so that archive/zip can locate structures correctly.
*/
func shiftZIPOffsets(zipData []byte, delta uint32) ([]byte, error) {
	if delta == 0 {
		return zipData, nil
	}
	result := make([]byte, len(zipData))
	copy(result, zipData)

	// Locate EOCD by scanning backward for its 4-byte signature.
	eocdOff := -1
	for i := len(result) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(result[i:]) == zipEOCDSig {
			eocdOff = i
			break
		}
	}
	if eocdOff < 0 {
		return nil, errors.New("EOCD signature not found in ZIP data")
	}

	// Patch EOCD: central directory offset is at bytes 16–19.
	cdOff := binary.LittleEndian.Uint32(result[eocdOff+16:])
	binary.LittleEndian.PutUint32(result[eocdOff+16:], cdOff+delta)

	// Walk central directory entries and patch each local-header offset.
	pos := int(cdOff)
	for pos < eocdOff {
		if pos+4 > len(result) {
			break
		}
		if binary.LittleEndian.Uint32(result[pos:]) != zipCDSig {
			break
		}
		// Local header offset is at central directory entry bytes 42–45.
		lhOff := binary.LittleEndian.Uint32(result[pos+42:])
		binary.LittleEndian.PutUint32(result[pos+42:], lhOff+delta)

		nameLen := int(binary.LittleEndian.Uint16(result[pos+28:]))
		extraLen := int(binary.LittleEndian.Uint16(result[pos+30:]))
		commentLen := int(binary.LittleEndian.Uint16(result[pos+32:]))
		pos += 46 + nameLen + extraLen + commentLen
	}

	return result, nil
}
