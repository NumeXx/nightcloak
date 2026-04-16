package native

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

/*
Unicode steganography via zero-width characters.

Payload is appended at the end of the host text as a block of invisible
Unicode chars. The block is framed by ZWNJ markers so it can be located
and stripped without touching the visible content.

Wire format appended to text:
  [ZWNJ x8][32-bit length as ZWSP/ZWJ bits][payload bits][ZWNJ x8]

Bit encoding: ZWSP (U+200B) = 0, ZWJ (U+200D) = 1, MSB first.
ZWNJ (U+200C) is used only as a frame marker, never as a bit carrier.

Supported carriers: .txt, .md, .html, .htm, .json, .xml, .csv
*/

const (
	runeZWSP = '\u200B' // zero-width space -- bit 0
	runeZWJ  = '\u200D' // zero-width joiner -- bit 1
	runeZWNJ = '\u200C' // zero-width non-joiner -- frame marker only
	markerN  = 8        // number of ZWNJ runes in each frame marker
)

// UnicodeInject appends wirePayload as invisible chars at the end of text.
func UnicodeInject(text, wirePayload []byte) []byte {
	var b strings.Builder
	b.Grow(len(text) + markerN*3 + (4+len(wirePayload))*8*3 + markerN*3)
	b.Write(text)
	writeMarker(&b)
	writeBits(&b, lengthBytes(wirePayload))
	writeBits(&b, wirePayload)
	writeMarker(&b)
	return []byte(b.String())
}

// UnicodeExtract finds and decodes the invisible payload block from data.
func UnicodeExtract(data []byte) ([]byte, error) {
	runes := []rune(string(data))

	start, ok := findMarker(runes, 0)
	if !ok {
		return nil, errors.New("no unicode payload found")
	}
	pos := start + markerN

	if pos+32 > len(runes) {
		return nil, errors.New("truncated: missing length prefix")
	}
	n, err := readUint32(runes, pos)
	if err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	pos += 32

	if n > 64<<20 {
		return nil, fmt.Errorf("payload length %d exceeds 64 MB sanity limit", n)
	}
	if pos+int(n)*8 > len(runes) {
		return nil, errors.New("truncated: not enough bits for payload")
	}

	out := make([]byte, n)
	for i := range out {
		b, err := readByte(runes, pos+i*8)
		if err != nil {
			return nil, fmt.Errorf("reading payload byte %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}

/* UnicodeWipe removes the invisible payload block from data.
   No password required -- the operation is purely structural. */
func UnicodeWipe(data []byte) ([]byte, error) {
	runes := []rune(string(data))

	start, ok := findMarker(runes, 0)
	if !ok {
		return nil, errors.New("no unicode payload found")
	}
	pos := start + markerN

	if pos+32 > len(runes) {
		return nil, errors.New("truncated: missing length prefix")
	}
	n, err := readUint32(runes, pos)
	if err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	blockEnd := pos + 32 + int(n)*8 + markerN

	if blockEnd > len(runes) {
		return nil, errors.New("truncated: block extends past end of file")
	}

	out := make([]rune, 0, len(runes)-(blockEnd-start))
	out = append(out, runes[:start]...)
	out = append(out, runes[blockEnd:]...)
	return []byte(string(out)), nil
}

// writeMarker writes markerN ZWNJ runes into b.
func writeMarker(b *strings.Builder) {
	for i := 0; i < markerN; i++ {
		b.WriteRune(runeZWNJ)
	}
}

// writeBits encodes each byte of data as 8 ZWSP/ZWJ runes, MSB first.
func writeBits(b *strings.Builder, data []byte) {
	for _, byt := range data {
		for bit := 7; bit >= 0; bit-- {
			if (byt>>bit)&1 == 1 {
				b.WriteRune(runeZWJ)
			} else {
				b.WriteRune(runeZWSP)
			}
		}
	}
}

// lengthBytes encodes len(data) as a 4-byte big-endian slice.
func lengthBytes(data []byte) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(data)))
	return buf[:]
}

/* findMarker scans runes starting at offset for markerN consecutive ZWNJ runes.
   Returns the index of the first ZWNJ in the found marker and true on success. */
func findMarker(runes []rune, offset int) (int, bool) {
	for i := offset; i <= len(runes)-markerN; i++ {
		found := true
		for j := 0; j < markerN; j++ {
			if runes[i+j] != runeZWNJ {
				found = false
				break
			}
		}
		if found {
			return i, true
		}
	}
	return -1, false
}

// readUint32 reads 32 ZWSP/ZWJ runes at pos and returns the uint32 value.
func readUint32(runes []rune, pos int) (uint32, error) {
	var out [4]byte
	for i := range out {
		b, err := readByte(runes, pos+i*8)
		if err != nil {
			return 0, err
		}
		out[i] = b
	}
	return binary.BigEndian.Uint32(out[:]), nil
}

// readByte reads 8 ZWSP/ZWJ runes at pos and reconstructs the byte, MSB first.
func readByte(runes []rune, pos int) (byte, error) {
	var b byte
	for j := 0; j < 8; j++ {
		b <<= 1
		switch runes[pos+j] {
		case runeZWJ:
			b |= 1
		case runeZWSP:
			// bit 0, nothing to do
		default:
			return 0, fmt.Errorf("unexpected rune U+%04X at position %d", runes[pos+j], pos+j)
		}
	}
	return b, nil
}
