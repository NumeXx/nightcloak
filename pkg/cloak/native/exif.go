package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

/*
EXIF APP1 injection uses the "Parallel APP1" strategy: a new APP1 segment
containing a minimal valid TIFF/EXIF structure is inserted before SOS,
leaving any existing APP1 (camera metadata) untouched.

The TIFF structure we construct:

	Byte 0:   TIFF Header  [MM][0x002A][offset=8]
	Byte 8:   IFD0         [1 entry: ExifIFDPointer -> 26]
	Byte 26:  EXIF sub-IFD [1 entry: UserComment -> 44]
	Byte 44:  UserComment  [\0\0\0\0\0\0\0\0][sentinel:16][payload]

All offsets are constants derived from fixed structure sizes.
Big Endian (MM) byte order is used throughout.
*/

const (
	markerAPP1 = 0xFFE1

	// EXIF identifier written before the TIFF header inside APP1.
	// "Exif" + two null bytes = 6 bytes.
	exifIdSize = 6

	// Fixed TIFF structure sizes.
	tiffHeaderSize = 8  // byte order (2) + magic (2) + IFD0 offset (4)
	ifdEntrySize   = 12 // tag (2) + type (2) + count (4) + value/offset (4)
	ifdOverhead    = 6  // entry count (2) + next IFD pointer (4)

	// Offsets within our constructed TIFF.
	ifd0Offset    = tiffHeaderSize                          // 8
	exifIFDOffset = ifd0Offset + ifdOverhead + ifdEntrySize // 8 + 6 + 12 = 26
	dataOffset    = exifIFDOffset + ifdOverhead + ifdEntrySize // 26 + 6 + 12 = 44

	// UserComment tag requires an 8-byte charset prefix.
	userCommentCharsetSize = 8

	// EXIF tag IDs.
	tagExifIFDPointer = 0x8769
	tagUserComment    = 0x9286

	// TIFF data types.
	typeLONG      = 4 // 4 bytes
	typeUNDEFINED = 7 // 1 byte

	// Max payload per APP1 segment.
	// APP1 length field is 16-bit: max 65535.
	// Subtract: length field itself (2) + exif ID (6) + TIFF structure (44) + charset (8) + sentinel (16).
	maxExifPayload = 65535 - 2 - exifIdSize - dataOffset - userCommentCharsetSize - sentinelSize
)

/*
JPEGExifInject writes a JPEG stream from r to w, inserting one or more
APP1 segments with valid EXIF/TIFF structures containing the payload
in the UserComment tag. Segments are inserted immediately before SOS.

For payloads exceeding ~65459 bytes, multiple APP1 segments are created,
each with a mode byte and chain header identical to the COM approach.
*/
func JPEGExifInject(r io.Reader, w io.Writer, payload []byte, password string) error {
	// Verify SOI.
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
	segments := buildExifSegments(sent, payload)

	// Stream markers until SOS.
	var marker [2]byte
	for {
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			return fmt.Errorf("reading marker: %w", err)
		}

		m := binary.BigEndian.Uint16(marker[:])

		if m == markerSOS {
			// Inject APP1 segment(s) before SOS.
			for _, seg := range segments {
				if _, err := w.Write(seg); err != nil {
					return fmt.Errorf("writing APP1 segment: %w", err)
				}
			}

			// Write SOS and stream the rest.
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			_, err := io.Copy(w, r)
			return err
		}

		// Copy non-SOS markers through.
		if isStandaloneMarker(m) {
			if _, err := w.Write(marker[:]); err != nil {
				return err
			}
			continue
		}

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
		if segLen < 2 {
			return fmt.Errorf("invalid segment length %d for marker %04X", segLen, m)
		}
		if _, err := io.CopyN(w, r, int64(segLen-2)); err != nil {
			return fmt.Errorf("copying segment %04X: %w", m, err)
		}
	}
}

/*
JPEGExifExtract reads a JPEG stream and returns the payload from an APP1
segment whose EXIF UserComment contains a matching sentinel.

It scans all APP1 segments, parses each one's TIFF structure to find the
UserComment tag, and checks the sentinel. Handles both single and chained
multi-segment payloads.
*/
func JPEGExifExtract(r io.Reader, password string) ([]byte, error) {
	var soi [2]byte
	if _, err := io.ReadFull(r, soi[:]); err != nil {
		return nil, fmt.Errorf("reading SOI: %w", err)
	}
	if binary.BigEndian.Uint16(soi[:]) != markerSOI {
		return nil, errors.New("not a valid JPEG file")
	}

	expectedSentinel := sentinel(password)

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

		if m == markerSOS || m == 0xFFD9 {
			break
		}

		if isStandaloneMarker(m) {
			continue
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("reading segment length: %w", err)
		}
		segLen := binary.BigEndian.Uint16(lenBuf[:])
		if segLen < 2 {
			return nil, fmt.Errorf("invalid segment length %d", segLen)
		}
		dataLen := int(segLen - 2)

		if m == markerAPP1 && dataLen > exifIdSize {
			// Buffer the APP1 data to parse TIFF structure.
			data := make([]byte, dataLen)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("reading APP1 data: %w", err)
			}

			// Check for "Exif\0\0" identifier.
			if string(data[:exifIdSize]) != "Exif\x00\x00" {
				continue // Not an EXIF APP1 (could be XMP).
			}

			userComment := extractUserComment(data[exifIdSize:])
			if userComment == nil {
				continue
			}

			// Strip the 8-byte charset prefix.
			if len(userComment) < userCommentCharsetSize {
				continue
			}
			commentData := userComment[userCommentCharsetSize:]

			// Parse sentinel + mode + payload (same format as COM).
			result, idx, total, err := parseCOMPayload(commentData, expectedSentinel)
			if err != nil {
				continue
			}

			if total == 1 {
				return result, nil
			}

			// Multi-segment chain.
			if chainBuf == nil {
				chainBuf = make([][]byte, total)
				chainTotal = total
			}
			if idx < chainTotal {
				chainBuf[idx] = result
			}

			complete := true
			for i := uint16(0); i < chainTotal; i++ {
				if chainBuf[i] == nil {
					complete = false
					break
				}
			}
			if complete {
				var combined []byte
				for _, b := range chainBuf {
					combined = append(combined, b...)
				}
				return combined, nil
			}
			continue
		}

		// Skip non-APP1 segment data.
		if _, err := io.CopyN(io.Discard, r, int64(dataLen)); err != nil {
			return nil, fmt.Errorf("skipping segment %04X: %w", m, err)
		}
	}

	if chainBuf != nil {
		for _, b := range chainBuf {
			if b == nil {
				return nil, errors.New("no nightcloak payload found in JPEG EXIF (incomplete chain)")
			}
		}
		var combined []byte
		for _, b := range chainBuf {
			combined = append(combined, b...)
		}
		return combined, nil
	}

	return nil, errors.New("no nightcloak payload found in JPEG EXIF")
}

/*
extractUserComment parses a TIFF byte stream and returns the raw
UserComment data, or nil if the tag is not found.

Navigation: TIFF header -> IFD0 -> ExifIFDPointer -> EXIF sub-IFD -> UserComment.
*/
func extractUserComment(tiff []byte) []byte {
	if len(tiff) < tiffHeaderSize {
		return nil
	}

	// Determine byte order.
	var bo binary.ByteOrder
	switch string(tiff[0:2]) {
	case "MM":
		bo = binary.BigEndian
	case "II":
		bo = binary.LittleEndian
	default:
		return nil
	}

	magic := bo.Uint16(tiff[2:4])
	if magic != 42 {
		return nil
	}

	ifd0Off := bo.Uint32(tiff[4:8])
	exifOff := findTagValue(tiff, bo, ifd0Off, tagExifIFDPointer)
	if exifOff == 0 {
		return nil
	}

	return findTagData(tiff, bo, exifOff, tagUserComment)
}

// findTagValue scans an IFD for a LONG tag and returns its 4-byte value.
func findTagValue(tiff []byte, bo binary.ByteOrder, ifdOff uint32, tagID uint16) uint32 {
	if int(ifdOff)+2 > len(tiff) {
		return 0
	}
	count := bo.Uint16(tiff[ifdOff : ifdOff+2])
	pos := ifdOff + 2

	for i := uint16(0); i < count; i++ {
		entryOff := pos + uint32(i)*ifdEntrySize
		if int(entryOff)+ifdEntrySize > len(tiff) {
			return 0
		}
		tag := bo.Uint16(tiff[entryOff : entryOff+2])
		if tag == tagID {
			return bo.Uint32(tiff[entryOff+8 : entryOff+12])
		}
	}
	return 0
}

// findTagData scans an IFD for a tag and returns its data bytes.
func findTagData(tiff []byte, bo binary.ByteOrder, ifdOff uint32, tagID uint16) []byte {
	if int(ifdOff)+2 > len(tiff) {
		return nil
	}
	count := bo.Uint16(tiff[ifdOff : ifdOff+2])
	pos := ifdOff + 2

	for i := uint16(0); i < count; i++ {
		entryOff := pos + uint32(i)*ifdEntrySize
		if int(entryOff)+ifdEntrySize > len(tiff) {
			return nil
		}
		tag := bo.Uint16(tiff[entryOff : entryOff+2])
		if tag != tagID {
			continue
		}

		typ := bo.Uint16(tiff[entryOff+2 : entryOff+4])
		cnt := bo.Uint32(tiff[entryOff+4 : entryOff+8])
		dataSize := cnt * tiffTypeSize(typ)

		if dataSize <= 4 {
			// Data is inline in the value/offset field.
			return tiff[entryOff+8 : entryOff+8+dataSize]
		}

		// Data is at an offset.
		off := bo.Uint32(tiff[entryOff+8 : entryOff+12])
		if int(off)+int(dataSize) > len(tiff) {
			return nil
		}
		return tiff[off : off+dataSize]
	}
	return nil
}

func tiffTypeSize(t uint16) uint32 {
	switch t {
	case 1, 2, 7: // BYTE, ASCII, UNDEFINED
		return 1
	case 3: // SHORT
		return 2
	case 4, 9: // LONG, SLONG
		return 4
	case 5, 10: // RATIONAL, SRATIONAL
		return 8
	default:
		return 1
	}
}

/*
buildExifSegments constructs one or more complete APP1 segment byte slices,
each containing a valid TIFF/EXIF structure with the payload in UserComment.

The mode byte and chain header format is shared with the COM injector
(parseCOMPayload) so the same extraction logic works for both.
*/
func buildExifSegments(sent, payload []byte) [][]byte {
	chunks := buildExifChunks(sent, payload)

	segments := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		segments[i] = buildAPP1Segment(chunk)
	}
	return segments
}

// buildExifChunks splits the payload into chunks that fit within
// the APP1 segment size limit after TIFF/EXIF overhead.
// Uses the same mode-byte + chain-header format as COM chunks.
func buildExifChunks(sent, payload []byte) [][]byte {
	singleMax := maxExifPayload - 1 // minus mode byte
	if len(payload) <= singleMax {
		chunk := make([]byte, 0, sentinelSize+1+len(payload))
		chunk = append(chunk, sent...)
		chunk = append(chunk, 0x00) // single mode
		chunk = append(chunk, payload...)
		return [][]byte{chunk}
	}

	chainHeaderSize := 5 // 1 mode + 2 total + 2 index
	chunkDataMax := maxExifPayload - chainHeaderSize
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

// buildAPP1Segment wraps UserComment data in a complete APP1/EXIF/TIFF structure.
func buildAPP1Segment(commentData []byte) []byte {
	// UserComment = 8-byte charset prefix + commentData.
	userCommentLen := userCommentCharsetSize + len(commentData)
	tiffLen := dataOffset + userCommentLen
	app1DataLen := exifIdSize + tiffLen
	totalLen := 2 + 2 + app1DataLen // marker (2) + length (2) + data

	buf := make([]byte, totalLen)
	pos := 0

	// APP1 marker.
	binary.BigEndian.PutUint16(buf[pos:], markerAPP1)
	pos += 2

	// Length (includes itself but not the marker).
	binary.BigEndian.PutUint16(buf[pos:], uint16(2+app1DataLen))
	pos += 2

	// "Exif\0\0"
	copy(buf[pos:], "Exif\x00\x00")
	pos += exifIdSize

	tiffStart := pos

	// TIFF Header: Big Endian, magic 42, IFD0 at offset 8.
	copy(buf[pos:], "MM")
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 42)
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], ifd0Offset)
	pos += 4

	// IFD0: 1 entry (ExifIFDPointer).
	binary.BigEndian.PutUint16(buf[pos:], 1) // entry count
	pos += 2

	// IFD0 Entry: ExifIFDPointer (tag 0x8769, type LONG, count 1, value = exifIFDOffset).
	binary.BigEndian.PutUint16(buf[pos:], tagExifIFDPointer)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], typeLONG)
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], 1)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], exifIFDOffset)
	pos += 4

	// Next IFD pointer: 0 (no more IFDs).
	binary.BigEndian.PutUint32(buf[pos:], 0)
	pos += 4

	// EXIF sub-IFD: 1 entry (UserComment).
	binary.BigEndian.PutUint16(buf[pos:], 1) // entry count
	pos += 2

	// EXIF Entry: UserComment (tag 0x9286, type UNDEFINED, count = userCommentLen).
	binary.BigEndian.PutUint16(buf[pos:], tagUserComment)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], typeUNDEFINED)
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(userCommentLen))
	pos += 4

	if userCommentLen <= 4 {
		// Inline (won't happen in practice — sentinel alone is 16 bytes).
		copy(buf[pos:], make([]byte, userCommentCharsetSize))
		copy(buf[pos+userCommentCharsetSize:], commentData)
		pos += 4
	} else {
		// Offset to data.
		binary.BigEndian.PutUint32(buf[pos:], dataOffset)
		pos += 4
	}

	// Next IFD pointer: 0.
	binary.BigEndian.PutUint32(buf[pos:], 0)
	pos += 4

	// UserComment data: 8 null bytes (undefined charset) + commentData.
	_ = tiffStart // suppress unused warning — tiffStart anchors offset math
	copy(buf[pos:], make([]byte, userCommentCharsetSize)) // 8x \0
	pos += userCommentCharsetSize
	copy(buf[pos:], commentData)

	return buf
}
