package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

/*
JPEG marker reference:

	0xFFD8  SOI  (Start of Image) — no length field
	0xFFD9  EOI  (End of Image)   — no length field
	0xFFDA  SOS  (Start of Scan)  — followed by entropy-coded image data
	0xFFFE  COM  (Comment)        — free-form, max 65533 bytes per segment
	0xFF00  Escaped 0xFF inside entropy data — NOT a marker
	0xFFE0-0xFFEF  APPn segments (APP0=JFIF, APP1=EXIF, etc.)

We inject COM segments immediately before SOS. Everything after SOS
(the compressed image data) passes through untouched.
*/

const (
	markerSOI = 0xFFD8
	markerSOS = 0xFFDA
	markerCOM = 0xFFFE

	// maxCOMData is the maximum data bytes in a single COM segment.
	// Length field is 16-bit and includes its own 2 bytes: 65535 - 2 = 65533.
	maxCOMData = 65533
)

/*
JPEGInject writes a JPEG stream from r to w, inserting one or more COM
segments containing the payload immediately before the SOS marker.

If the payload (sentinel + data) exceeds 65533 bytes, it is split across
multiple chained COM segments. The first segment carries a 4-byte chain
header [total_segments:2][segment_index:2] after the sentinel, so the
extractor knows how to reassemble.

Streaming: markers are identified by reading 2 bytes at a time. Non-target
segments are copied via io.CopyN. The entropy-coded data after SOS passes
through without parsing.
*/
func JPEGInject(r io.Reader, w io.Writer, payload []byte, password string) error {
	// Verify SOI marker.
	var soi [2]byte
	if _, err := io.ReadFull(r, soi[:]); err != nil {
		return fmt.Errorf("reading SOI: %w", err)
	}
	if binary.BigEndian.Uint16(soi[:]) != markerSOI {
		return errors.New("not a valid JPEG file")
	}
	if _, err := w.Write(soi[:]); err != nil {
		return err
	}

	sent := sentinel(password)
	chunks := buildCOMChunks(sent, payload)

	// Stream markers until SOS.
	var marker [2]byte
	for {
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			return fmt.Errorf("reading marker: %w", err)
		}

		m := binary.BigEndian.Uint16(marker[:])

		if m == markerSOS {
			// Inject COM segment(s) right before SOS.
			for _, chunk := range chunks {
				if err := writeCOMSegment(w, chunk); err != nil {
					return fmt.Errorf("writing COM segment: %w", err)
				}
			}

			// Write SOS marker, then copy the rest of the stream
			// (entropy data + EOI) verbatim.
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			_, err := io.Copy(w, r)
			return err
		}

		// Standalone markers (no length field): just copy through.
		// In practice, between SOI and SOS we only encounter markers
		// with length fields, but handle the edge case.
		if isStandaloneMarker(m) {
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			continue
		}

		// Marker with length field — read length, copy segment through.
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return fmt.Errorf("reading segment length: %w", err)
		}
		segLen := binary.BigEndian.Uint16(lenBuf[:])

		if _, err := w.Write(marker[:]); err != nil {
			return err
		}
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		// Copy segment data (segLen includes the 2 length bytes themselves).
		if segLen < 2 {
			return fmt.Errorf("invalid segment length %d for marker %04X", segLen, m)
		}
		if _, err := io.CopyN(w, r, int64(segLen-2)); err != nil {
			return fmt.Errorf("copying segment %04X: %w", m, err)
		}
	}
}

/*
JPEGExtract reads a JPEG stream and returns the payload from the COM
segment(s) whose sentinel matches the given password.

Handles both single-segment and multi-segment (chained) payloads.
Non-matching COM segments and all other segments are skipped efficiently.
*/
func JPEGExtract(r io.Reader, password string) ([]byte, error) {
	var soi [2]byte
	if _, err := io.ReadFull(r, soi[:]); err != nil {
		return nil, fmt.Errorf("reading SOI: %w", err)
	}
	if binary.BigEndian.Uint16(soi[:]) != markerSOI {
		return nil, errors.New("not a valid JPEG file")
	}

	expectedSentinel := sentinel(password)

	// Collect chain segments if we find a multi-segment payload.
	var chainBuf [][]byte
	var chainTotal uint16

	var marker [2]byte
	for {
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, fmt.Errorf("reading marker: %w", err)
		}

		m := binary.BigEndian.Uint16(marker[:])

		// SOS or EOI — done scanning markers.
		if m == markerSOS || m == 0xFFD9 {
			break
		}

		if isStandaloneMarker(m) {
			continue
		}

		// Read segment length.
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("reading segment length: %w", err)
		}
		segLen := binary.BigEndian.Uint16(lenBuf[:])
		if segLen < 2 {
			return nil, fmt.Errorf("invalid segment length %d", segLen)
		}
		dataLen := int(segLen - 2)

		if m == markerCOM {
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("reading COM data: %w", err)
			}

			result, segments, total, err := parseCOMPayload(data, expectedSentinel)
			if err != nil {
				continue // sentinel mismatch, skip
			}

			if total == 1 {
				// Single-segment payload — return immediately.
				return result, nil
			}

			// Multi-segment: accumulate.
			if chainBuf == nil {
				chainBuf = make([][]byte, total)
				chainTotal = total
			}
			if segments < chainTotal {
				chainBuf[segments] = result
			}

			// Check if chain is complete.
			complete := true
			for i := uint16(0); i < chainTotal; i++ {
				if chainBuf[i] == nil {
					complete = false
					break
				}
			}
			if complete {
				return bytes.Join(chainBuf, nil), nil
			}
			continue
		}

		// Skip non-COM segment data.
		if _, err := io.CopyN(io.Discard, r, int64(dataLen)); err != nil {
			return nil, fmt.Errorf("skipping segment %04X: %w", m, err)
		}
	}

	// Check if we assembled a partial chain.
	if chainBuf != nil {
		// Return what we have if all pieces collected.
		for _, b := range chainBuf {
			if b == nil {
				return nil, errors.New("no nightcloak payload found in JPEG (incomplete chain)")
			}
		}
		return bytes.Join(chainBuf, nil), nil
	}

	return nil, errors.New("no nightcloak payload found in JPEG")
}

/*
buildCOMChunks splits the payload into COM-sized chunks.

Single-segment format (payload + sentinel + mode byte <= maxCOMData):

	[sentinel:16][0x00 (single mode)][payload]

Multi-segment format (each chunk):

	[sentinel:16][0x01 (chain mode)][total:2][index:2][payload_chunk]
*/
func buildCOMChunks(sent, payload []byte) [][]byte {
	// 1 byte for mode flag.
	singleMax := maxCOMData - sentinelSize - 1
	if len(payload) <= singleMax {
		chunk := make([]byte, 0, sentinelSize+1+len(payload))
		chunk = append(chunk, sent...)
		chunk = append(chunk, 0x00) // single-segment mode
		chunk = append(chunk, payload...)
		return [][]byte{chunk}
	}

	// Multi-segment: mode byte + 4-byte chain header per segment.
	chainHeaderSize := 5 // 1 mode + 2 total + 2 index
	chunkDataMax := maxCOMData - sentinelSize - chainHeaderSize
	totalSegments := (len(payload) + chunkDataMax - 1) / chunkDataMax

	chunks := make([][]byte, totalSegments)
	for i := 0; i < totalSegments; i++ {
		start := i * chunkDataMax
		end := start + chunkDataMax
		if end > len(payload) {
			end = len(payload)
		}
		piece := payload[start:end]

		chunk := make([]byte, 0, sentinelSize+chainHeaderSize+len(piece))
		chunk = append(chunk, sent...)
		chunk = append(chunk, 0x01) // chain mode

		var hdr [4]byte
		binary.BigEndian.PutUint16(hdr[0:2], uint16(totalSegments))
		binary.BigEndian.PutUint16(hdr[2:4], uint16(i))
		chunk = append(chunk, hdr[:]...)
		chunk = append(chunk, piece...)

		chunks[i] = chunk
	}
	return chunks
}

/*
parseCOMPayload checks if a COM segment's data matches our sentinel
and extracts the payload.

Returns: (payload, segmentIndex, totalSegments, error)

Mode byte after sentinel: 0x00 = single segment, 0x01 = chained.
*/
func parseCOMPayload(data, expectedSentinel []byte) ([]byte, uint16, uint16, error) {
	// Minimum: sentinel (16) + mode byte (1).
	if len(data) < sentinelSize+1 {
		return nil, 0, 0, errors.New("too short")
	}

	if !bytes.Equal(data[:sentinelSize], expectedSentinel) {
		return nil, 0, 0, errors.New("sentinel mismatch")
	}

	mode := data[sentinelSize]
	rest := data[sentinelSize+1:]

	switch mode {
	case 0x00:
		// Single segment.
		return rest, 0, 1, nil
	case 0x01:
		// Chain mode: [total:2][index:2][payload_chunk].
		if len(rest) < 4 {
			return nil, 0, 0, errors.New("chain header too short")
		}
		total := binary.BigEndian.Uint16(rest[0:2])
		index := binary.BigEndian.Uint16(rest[2:4])
		if index >= total || total == 0 {
			return nil, 0, 0, errors.New("invalid chain header")
		}
		return rest[4:], index, total, nil
	default:
		return nil, 0, 0, fmt.Errorf("unknown mode byte: %02x", mode)
	}
}

// writeCOMSegment writes a single JPEG COM segment: marker + length + data.
func writeCOMSegment(w io.Writer, data []byte) error {
	// Marker: 0xFFFE
	if _, err := w.Write([]byte{0xFF, 0xFE}); err != nil {
		return err
	}

	// Length: data size + 2 (length field includes itself).
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)+2))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}

	_, err := w.Write(data)
	return err
}

// isStandaloneMarker returns true for JPEG markers that have no length field.
// These are: SOI (D8), EOI (D9), RST0-RST7 (D0-D7), and TEM (01).
func isStandaloneMarker(m uint16) bool {
	b := byte(m & 0xFF)
	return m&0xFF00 == 0xFF00 && (b == 0xD8 || b == 0xD9 || (b >= 0xD0 && b <= 0xD7) || b == 0x01)
}
