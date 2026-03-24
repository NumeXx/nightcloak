package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

/*
Native ID3v2 injection for MP3 files. Injects a TXXX frame with the
description "ENCODEDBY" into the ID3v2 tag at the start of the file.

The injector handles three cases:
  - Existing tag with sufficient padding: frame is written into padding,
    no audio data shift required.
  - Existing tag with insufficient padding: tag is expanded, audio data
    is streamed after the new tag.
  - No ID3v2 tag: a new ID3v2.3 tag is created with 1KB padding.

All audio data (MPEG frames) passes through via io.Copy — never buffered.
*/

const (
	id3HeaderSize  = 10
	frameHeaderV23 = 10 // ID(4) + Size(4) + Flags(2)
	defaultPadding = 1024
	txDescription  = "ENCODEDBY"
)

// decodeSyncsafe decodes a 4-byte syncsafe integer (7 bits per byte).
func decodeSyncsafe(b []byte) uint32 {
	return uint32(b[0])<<21 | uint32(b[1])<<14 | uint32(b[2])<<7 | uint32(b[3])
}

// encodeSyncsafe encodes a uint32 as a 4-byte syncsafe integer.
func encodeSyncsafe(n uint32) [4]byte {
	return [4]byte{
		byte((n >> 21) & 0x7F),
		byte((n >> 14) & 0x7F),
		byte((n >> 7) & 0x7F),
		byte(n & 0x7F),
	}
}

/*
MP3Inject writes an MP3 stream from r to w, injecting a TXXX:ENCODEDBY
frame containing the payload into the ID3v2 tag.
*/
func MP3Inject(r io.Reader, w io.Writer, payload []byte, password string) error {
	// Read enough to check for ID3v2 header.
	header := make([]byte, id3HeaderSize)
	n, err := io.ReadFull(r, header)
	if err != nil && n < 3 {
		return fmt.Errorf("reading header: %w", err)
	}

	sent := sentinel(password)
	txxxFrame := buildTXXXFrame(sent, payload, 3) // default to v2.3 encoding

	hasID3 := n >= 3 && string(header[0:3]) == "ID3"

	if !hasID3 {
		// No existing ID3v2 tag. Create a new one.
		return injectNewTag(w, header[:n], r, txxxFrame)
	}

	// Parse existing ID3v2 header.
	version := header[3] // 3 = v2.3, 4 = v2.4
	flags := header[5]
	tagSize := decodeSyncsafe(header[6:10])

	// Rebuild TXXX frame with correct version encoding if v2.4.
	if version == 4 {
		txxxFrame = buildTXXXFrame(sent, payload, 4)
	}

	// Read the entire tag body (bounded by tagSize).
	tagBody := make([]byte, tagSize)
	if _, err := io.ReadFull(r, tagBody); err != nil {
		return fmt.Errorf("reading tag body: %w", err)
	}

	// Handle extended header if present.
	frameStart := uint32(0)
	if flags&0x40 != 0 {
		if len(tagBody) < 4 {
			return errors.New("truncated extended header")
		}
		var extSize uint32
		if version == 4 {
			extSize = decodeSyncsafe(tagBody[0:4])
		} else {
			extSize = binary.BigEndian.Uint32(tagBody[0:4])
		}
		frameStart = extSize
	}

	// Walk existing frames, find end of frames (start of padding).
	framesEnd := findFramesEnd(tagBody, frameStart, version)

	// Check for existing TXXX:ENCODEDBY and remove it.
	tagBody, framesEnd = removeTXXXFrame(tagBody, frameStart, framesEnd, version, txDescription)

	existingPadding := tagSize - framesEnd
	neededSpace := uint32(len(txxxFrame))

	if neededSpace <= existingPadding {
		// Fits in existing padding. Write frame into padding area, keep tag size.
		copy(tagBody[framesEnd:], txxxFrame)
		// Zero remaining padding after our frame.
		remaining := existingPadding - neededSpace
		for i := uint32(0); i < remaining; i++ {
			tagBody[framesEnd+neededSpace+i] = 0x00
		}

		// Write original header (tag size unchanged).
		if _, err := w.Write(header); err != nil {
			return err
		}
		if _, err := w.Write(tagBody); err != nil {
			return err
		}
	} else {
		// Need to expand the tag. New size = frames + our frame + padding.
		newTagSize := framesEnd + neededSpace + defaultPadding
		ss := encodeSyncsafe(newTagSize)

		// Write updated header.
		newHeader := make([]byte, id3HeaderSize)
		copy(newHeader, header)
		copy(newHeader[6:10], ss[:])
		if _, err := w.Write(newHeader); err != nil {
			return err
		}

		// Write existing frames (up to framesEnd).
		if _, err := w.Write(tagBody[:framesEnd]); err != nil {
			return err
		}

		// Write our TXXX frame.
		if _, err := w.Write(txxxFrame); err != nil {
			return err
		}

		// Write padding.
		padding := make([]byte, defaultPadding)
		if _, err := w.Write(padding); err != nil {
			return err
		}
	}

	// Stream the audio data through.
	_, err = io.Copy(w, r)
	return err
}

/*
MP3Extract reads an MP3 stream and returns the payload from the
TXXX:ENCODEDBY frame whose sentinel matches the given password.
*/
func MP3Extract(r io.Reader, password string) ([]byte, error) {
	header := make([]byte, id3HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}
	if string(header[0:3]) != "ID3" {
		return nil, errors.New("no ID3v2 tag found in MP3")
	}

	version := header[3]
	flags := header[5]
	tagSize := decodeSyncsafe(header[6:10])

	tagBody := make([]byte, tagSize)
	if _, err := io.ReadFull(r, tagBody); err != nil {
		return nil, fmt.Errorf("reading tag body: %w", err)
	}

	// Skip extended header if present.
	frameStart := uint32(0)
	if flags&0x40 != 0 {
		if len(tagBody) < 4 {
			return nil, errors.New("truncated extended header")
		}
		var extSize uint32
		if version == 4 {
			extSize = decodeSyncsafe(tagBody[0:4])
		} else {
			extSize = binary.BigEndian.Uint32(tagBody[0:4])
		}
		frameStart = extSize
	}

	expectedSentinel := sentinel(password)
	pos := frameStart

	for pos+frameHeaderV23 <= uint32(len(tagBody)) {
		frameID := string(tagBody[pos : pos+4])

		// End of frames: null bytes or invalid frame ID.
		if frameID[0] == 0x00 {
			break
		}

		var frameSize uint32
		if version == 4 {
			frameSize = decodeSyncsafe(tagBody[pos+4 : pos+8])
		} else {
			frameSize = binary.BigEndian.Uint32(tagBody[pos+4 : pos+8])
		}

		frameData := tagBody[pos+frameHeaderV23 : pos+frameHeaderV23+frameSize]

		if frameID == "TXXX" {
			desc, value := parseTXXXData(frameData)
			if desc == txDescription && len(value) >= sentinelSize+1 {
				result, _, _, err := parseCOMPayload(value, expectedSentinel)
				if err == nil {
					return result, nil
				}
			}
		}

		pos += frameHeaderV23 + frameSize
	}

	return nil, errors.New("no nightcloak payload found in MP3")
}

// buildTXXXFrame constructs a complete TXXX frame with header.
//
// Frame data: [encoding:1][description\0][sentinel+mode+payload]
func buildTXXXFrame(sent, payload []byte, version byte) []byte {
	// Build the value: sentinel + mode byte + payload (same as COM/EXIF).
	var value []byte
	value = append(value, sent...)
	value = append(value, 0x00) // single-segment mode
	value = append(value, payload...)

	// Frame data: encoding(1) + description + null(1) + value.
	desc := []byte(txDescription)
	frameData := make([]byte, 0, 1+len(desc)+1+len(value))
	frameData = append(frameData, 0x00) // ISO-8859-1 encoding
	frameData = append(frameData, desc...)
	frameData = append(frameData, 0x00) // null terminator
	frameData = append(frameData, value...)

	// Frame header: ID(4) + Size(4) + Flags(2).
	frame := make([]byte, frameHeaderV23+len(frameData))
	copy(frame[0:4], "TXXX")

	if version == 4 {
		ss := encodeSyncsafe(uint32(len(frameData)))
		copy(frame[4:8], ss[:])
	} else {
		binary.BigEndian.PutUint32(frame[4:8], uint32(len(frameData)))
	}

	// Flags: 0x0000 (no compression, no encryption).
	frame[8] = 0x00
	frame[9] = 0x00

	copy(frame[frameHeaderV23:], frameData)
	return frame
}

// parseTXXXData parses a TXXX frame's data into description and value.
func parseTXXXData(data []byte) (string, []byte) {
	if len(data) < 2 {
		return "", nil
	}

	// First byte is text encoding. We only handle 0x00 (ISO-8859-1).
	encoding := data[0]
	rest := data[1:]

	var nullTerm []byte
	switch encoding {
	case 0x00, 0x03: // ISO-8859-1 or UTF-8: single null terminator
		nullTerm = []byte{0x00}
	case 0x01, 0x02: // UTF-16: double null terminator
		nullTerm = []byte{0x00, 0x00}
	default:
		nullTerm = []byte{0x00}
	}

	idx := bytes.Index(rest, nullTerm)
	if idx < 0 {
		return string(rest), nil
	}

	desc := string(rest[:idx])
	value := rest[idx+len(nullTerm):]
	return desc, value
}

// findFramesEnd walks ID3v2 frames and returns the byte offset where
// frames end (start of padding or end of tag).
func findFramesEnd(tagBody []byte, start uint32, version byte) uint32 {
	pos := start
	for pos+frameHeaderV23 <= uint32(len(tagBody)) {
		// Null byte means we've hit padding.
		if tagBody[pos] == 0x00 {
			break
		}

		// Validate frame ID (must be uppercase A-Z or 0-9).
		valid := true
		for i := 0; i < 4; i++ {
			c := tagBody[pos+uint32(i)]
			if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
				valid = false
				break
			}
		}
		if !valid {
			break
		}

		var frameSize uint32
		if version == 4 {
			frameSize = decodeSyncsafe(tagBody[pos+4 : pos+8])
		} else {
			frameSize = binary.BigEndian.Uint32(tagBody[pos+4 : pos+8])
		}

		if frameSize == 0 {
			break
		}

		next := pos + frameHeaderV23 + frameSize
		if next > uint32(len(tagBody)) {
			break
		}
		pos = next
	}
	return pos
}

// removeTXXXFrame removes an existing TXXX frame with the given description
// from the tag body. Returns the modified body and new framesEnd.
func removeTXXXFrame(tagBody []byte, start, framesEnd uint32, version byte, targetDesc string) ([]byte, uint32) {
	pos := start
	for pos+frameHeaderV23 <= framesEnd {
		frameID := string(tagBody[pos : pos+4])
		if frameID[0] == 0x00 {
			break
		}

		var frameSize uint32
		if version == 4 {
			frameSize = decodeSyncsafe(tagBody[pos+4 : pos+8])
		} else {
			frameSize = binary.BigEndian.Uint32(tagBody[pos+4 : pos+8])
		}

		totalFrameSize := uint32(frameHeaderV23) + frameSize

		if frameID == "TXXX" {
			frameData := tagBody[pos+frameHeaderV23 : pos+frameHeaderV23+frameSize]
			desc, _ := parseTXXXData(frameData)
			if desc == targetDesc {
				// Remove this frame by shifting subsequent data left.
				copy(tagBody[pos:], tagBody[pos+totalFrameSize:])
				// Zero the freed space at the end.
				newEnd := framesEnd - totalFrameSize
				for i := newEnd; i < framesEnd; i++ {
					tagBody[i] = 0x00
				}
				return tagBody, newEnd
			}
		}

		pos += totalFrameSize
	}
	return tagBody, framesEnd
}

// injectNewTag creates a fresh ID3v2.3 tag when the MP3 has none.
func injectNewTag(w io.Writer, initialBytes []byte, r io.Reader, txxxFrame []byte) error {
	tagSize := uint32(len(txxxFrame)) + defaultPadding
	ss := encodeSyncsafe(tagSize)

	// ID3v2.3 header.
	header := []byte{
		'I', 'D', '3',
		0x03, 0x00, // version 2.3
		0x00,       // no flags
		ss[0], ss[1], ss[2], ss[3],
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(txxxFrame); err != nil {
		return err
	}

	padding := make([]byte, defaultPadding)
	if _, err := w.Write(padding); err != nil {
		return err
	}

	// Write back the initial bytes we already read (they're audio data).
	if _, err := w.Write(initialBytes); err != nil {
		return err
	}

	// Stream the rest of the audio.
	_, err := io.Copy(w, r)
	return err
}
