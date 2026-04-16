/*
Package native provides zero-dependency metadata injection for common
image formats. No external tools (exiftool, ffmpeg) are required.

PNG: injects payloads via tEXt chunks. Streaming, never loads the full
carrier into memory.
*/
package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// PNG magic bytes: the 8-byte signature that starts every valid PNG file.
var pngSignature = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

const (
	chunkHeaderSize = 8  // 4B length + 4B type
	chunkCRCSize    = 4  // 4B CRC32
	sentinelSize    = 16 // HMAC-derived sentinel prefix
	textKeyword     = "Description"
	iendType        = "IEND"
	textType        = "tEXt"
)

// sentinel derives a 16-byte password-specific marker using HMAC-SHA256.
// This replaces the static "Modified by Cloak" string. The extractor
// computes the same sentinel from the password to locate its payload
// among potentially many tEXt chunks.
func sentinel(password string) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("nightcloak"))
	return mac.Sum(nil)[:sentinelSize]
}

/*
PNGInject writes a PNG stream from r to w, inserting a tEXt chunk
containing the payload immediately before the IEND chunk.

The tEXt chunk data layout:

	[keyword "Description"][null byte][sentinel: 16B][payload bytes]

Streaming: chunks are copied verbatim via io.CopyN. Only the 8-byte
chunk headers are read into memory to determine type and length.
The carrier's image data (IDAT) passes through untouched.
*/
func PNGInject(r io.Reader, w io.Writer, payload []byte, password string) error {
	// Verify PNG signature.
	sig := make([]byte, 8)
	if _, err := io.ReadFull(r, sig); err != nil {
		return fmt.Errorf("reading PNG signature: %w", err)
	}
	if !bytes.Equal(sig, pngSignature) {
		return errors.New("not a valid PNG file")
	}
	if _, err := w.Write(sig); err != nil {
		return fmt.Errorf("writing PNG signature: %w", err)
	}

	// Build the tEXt chunk data: keyword + null + sentinel + payload.
	sent := sentinel(password)
	textData := make([]byte, 0, len(textKeyword)+1+sentinelSize+len(payload))
	textData = append(textData, textKeyword...)
	textData = append(textData, 0x00) // null separator
	textData = append(textData, sent...)
	textData = append(textData, payload...)

	// Stream chunks until IEND. Insert our tEXt chunk right before it.
	header := make([]byte, chunkHeaderSize)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return fmt.Errorf("reading chunk header: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(header[0:4])
		chunkType := string(header[4:8])

		if chunkType == iendType {
			// Inject our tEXt chunk before IEND.
			if err := writeTextChunk(w, textData); err != nil {
				return fmt.Errorf("writing tEXt chunk: %w", err)
			}

			// Write the IEND chunk (header + data + CRC).
			if _, err := w.Write(header); err != nil {
				return err
			}
			// IEND has 0 data bytes, but still has a CRC.
			crcBuf := make([]byte, chunkCRCSize)
			if _, err := io.ReadFull(r, crcBuf); err != nil {
				return fmt.Errorf("reading IEND CRC: %w", err)
			}
			_, err := w.Write(crcBuf)
			return err
		}

		// Not IEND — copy this chunk through verbatim.
		// Write header, then copy data + CRC as a single block.
		if _, err := w.Write(header); err != nil {
			return err
		}
		remaining := int64(chunkLen) + chunkCRCSize
		if _, err := io.CopyN(w, r, remaining); err != nil {
			return fmt.Errorf("copying chunk %s: %w", chunkType, err)
		}
	}
}

/*
PNGExtract reads a PNG stream and returns the payload from the first
tEXt chunk whose sentinel matches the given password.

Streaming: non-matching chunks are skipped via io.CopyN to /dev/null.
Only matching tEXt chunk data is read into memory.
*/
func PNGExtract(r io.Reader, password string) ([]byte, error) {
	// Verify PNG signature.
	sig := make([]byte, 8)
	if _, err := io.ReadFull(r, sig); err != nil {
		return nil, fmt.Errorf("reading PNG signature: %w", err)
	}
	if !bytes.Equal(sig, pngSignature) {
		return nil, errors.New("not a valid PNG file")
	}

	expectedSentinel := sentinel(password)
	header := make([]byte, chunkHeaderSize)

	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil, errors.New("no nightcloak payload found in PNG")
			}
			return nil, fmt.Errorf("reading chunk header: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(header[0:4])
		chunkType := string(header[4:8])

		if chunkType == iendType {
			return nil, errors.New("no nightcloak payload found in PNG")
		}

		if chunkType == textType {
			// Read the full tEXt chunk data + CRC.
			chunkData := make([]byte, chunkLen)
			if _, err := io.ReadFull(r, chunkData); err != nil {
				return nil, fmt.Errorf("reading tEXt data: %w", err)
			}
			// Skip CRC (we don't need to verify on read — the PNG decoder will).
			if _, err := io.CopyN(io.Discard, r, chunkCRCSize); err != nil {
				return nil, fmt.Errorf("skipping tEXt CRC: %w", err)
			}

			// Parse: keyword + null + sentinel + payload.
			nullIdx := bytes.IndexByte(chunkData, 0x00)
			if nullIdx < 0 {
				continue // malformed tEXt, skip
			}
			value := chunkData[nullIdx+1:]

			// Check sentinel.
			if len(value) < sentinelSize {
				continue
			}
			if hmac.Equal(value[:sentinelSize], expectedSentinel) {
				return value[sentinelSize:], nil
			}
			continue // sentinel doesn't match, not ours
		}

		// Skip non-tEXt chunks (data + CRC).
		skip := int64(chunkLen) + chunkCRCSize
		if _, err := io.CopyN(io.Discard, r, skip); err != nil {
			return nil, fmt.Errorf("skipping chunk %s: %w", chunkType, err)
		}
	}
}

// writeTextChunk writes a complete tEXt chunk to w.
func writeTextChunk(w io.Writer, data []byte) error {
	// Length: 4 bytes big-endian.
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}

	// Type: "tEXt"
	typeBytes := []byte(textType)
	if _, err := w.Write(typeBytes); err != nil {
		return err
	}

	// Data.
	if _, err := w.Write(data); err != nil {
		return err
	}

	// CRC32 over type + data.
	crc := crc32.NewIEEE()
	crc.Write(typeBytes)
	crc.Write(data)
	crcBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBuf, crc.Sum32())
	_, err := w.Write(crcBuf)
	return err
}
