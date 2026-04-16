package shard

/*
Reed-Solomon erasure coding with self-describing shard manifests.

A (K, P) scheme splits a payload into K data shards plus P parity shards.
Any K of the K+P total shards are sufficient to reconstruct the payload —
up to P shards may be lost or corrupted.

Manifest wire format (52 bytes, big-endian):
  Offset  Size  Field
  ------  ----  -----
  0       4     Magic: 0x4E434C53 ("NCLS")
  4       1     Version (0x01)
  5       1     ShardIndex (0-indexed)
  6       1     DataShards K
  7       1     ParityShards P
  8       8     OriginalSize (original payload byte count)
  16      32    PayloadID = HMAC-SHA256(password, SHA256(payload) || "nightcloak-shard-set-v1")
  48      4     ShardDataLen (byte count of the following shard data)
  ---
  52      N     Shard data bytes

PayloadID is unique per (password, payload) pair, allowing the scanner to
group shards from the same split operation without leaking the password.
*/

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	ManifestSize    = 52
	manifestVersion = 0x01
)

var manifestMagic = [4]byte{'N', 'C', 'L', 'S'}

// Manifest is the 52-byte self-describing header at the start of each shard.
type Manifest struct {
	Magic        [4]byte
	Version      byte
	ShardIndex   byte
	DataShards   byte
	ParityShards byte
	OriginalSize uint64
	PayloadID    [32]byte
	ShardDataLen uint32
}

func encodeManifest(m Manifest) []byte {
	b := make([]byte, ManifestSize)
	copy(b[0:4], m.Magic[:])
	b[4] = m.Version
	b[5] = m.ShardIndex
	b[6] = m.DataShards
	b[7] = m.ParityShards
	binary.BigEndian.PutUint64(b[8:16], m.OriginalSize)
	copy(b[16:48], m.PayloadID[:])
	binary.BigEndian.PutUint32(b[48:52], m.ShardDataLen)
	return b
}

/* DecodeManifest parses a manifest from the first ManifestSize bytes of b.
Exported so callers can inspect shard metadata without calling Join. */
func DecodeManifest(b []byte) (Manifest, error) {
	if len(b) < ManifestSize {
		return Manifest{}, fmt.Errorf("need %d bytes for manifest, got %d", ManifestSize, len(b))
	}
	var m Manifest
	copy(m.Magic[:], b[0:4])
	if m.Magic != manifestMagic {
		return Manifest{}, fmt.Errorf("bad magic %x (not a NightCloak shard)", m.Magic)
	}
	m.Version = b[4]
	m.ShardIndex = b[5]
	m.DataShards = b[6]
	m.ParityShards = b[7]
	m.OriginalSize = binary.BigEndian.Uint64(b[8:16])
	copy(m.PayloadID[:], b[16:48])
	m.ShardDataLen = binary.BigEndian.Uint32(b[48:52])
	return m, nil
}

/* derivePayloadID computes the per-payload identifier embedded in each manifest.
Unique per (password, payload) pair, allows grouping without exposing the password. */
func derivePayloadID(password string, payload []byte) [32]byte {
	payloadHash := sha256.Sum256(payload)
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(payloadHash[:])
	mac.Write([]byte("nightcloak-shard-set-v1"))
	var id [32]byte
	copy(id[:], mac.Sum(nil))
	return id
}

/*
Split encodes payload into K data shards + P parity shards using Reed-Solomon.
Returns K+P byte slices, each prefixed by a 52-byte manifest.
Any K slices are sufficient to reconstruct the original payload via Join.
*/
func Split(payload []byte, dataShards, parityShards int, password string) ([][]byte, error) {
	if dataShards < 1 {
		return nil, fmt.Errorf("dataShards must be >= 1, got %d", dataShards)
	}
	if parityShards < 0 {
		return nil, fmt.Errorf("parityShards must be >= 0, got %d", parityShards)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("creating Reed-Solomon encoder: %w", err)
	}

	shards, err := enc.Split(payload)
	if err != nil {
		return nil, fmt.Errorf("splitting payload: %w", err)
	}
	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding parity shards: %w", err)
	}

	id := derivePayloadID(password, payload)
	n := dataShards + parityShards
	result := make([][]byte, n)

	for i, shard := range shards {
		m := Manifest{
			Magic:        manifestMagic,
			Version:      manifestVersion,
			ShardIndex:   byte(i),
			DataShards:   byte(dataShards),
			ParityShards: byte(parityShards),
			OriginalSize: uint64(len(payload)),
			PayloadID:    id,
			ShardDataLen: uint32(len(shard)),
		}
		encoded := make([]byte, ManifestSize+len(shard))
		copy(encoded[:ManifestSize], encodeManifest(m))
		copy(encoded[ManifestSize:], shard)
		result[i] = encoded
	}
	return result, nil
}

/*
Join reconstructs the original payload from available encoded shards.

encodedShards must be a slice of length K+P where each element is either:
  - the encoded shard bytes (manifest header + shard data), or
  - nil for a missing/lost shard.

At least K non-nil shards are required. Trailing bytes beyond the manifest
and shard data (e.g. beacon alignment padding) are ignored.
*/
func Join(encodedShards [][]byte, password string) ([]byte, error) {
	// Find first available shard to read the manifest parameters.
	var ref *Manifest
	for _, enc := range encodedShards {
		if enc == nil {
			continue
		}
		m, err := DecodeManifest(enc)
		if err != nil {
			return nil, fmt.Errorf("decoding manifest: %w", err)
		}
		ref = &m
		break
	}
	if ref == nil {
		return nil, errors.New("all shards are nil — no data to reconstruct")
	}

	k := int(ref.DataShards)
	p := int(ref.ParityShards)
	n := k + p

	if len(encodedShards) != n {
		return nil, fmt.Errorf("expected %d shard slots, got %d", n, len(encodedShards))
	}

	// Extract raw shard byte slices, validating each manifest.
	rawShards := make([][]byte, n)
	for i, enc := range encodedShards {
		if enc == nil {
			continue // will be reconstructed from parity
		}
		m, err := DecodeManifest(enc)
		if err != nil {
			return nil, fmt.Errorf("shard slot %d: %w", i, err)
		}
		if m.PayloadID != ref.PayloadID {
			return nil, fmt.Errorf("shard slot %d: payload ID mismatch (wrong shard set)", i)
		}
		if int(m.ShardIndex) != i {
			return nil, fmt.Errorf("shard slot %d: manifest index field is %d", i, m.ShardIndex)
		}
		// Use ShardDataLen to slice exactly — ignores beacon alignment padding.
		end := ManifestSize + int(m.ShardDataLen)
		if end > len(enc) {
			return nil, fmt.Errorf("shard slot %d: declared length %d exceeds byte slice %d", i, m.ShardDataLen, len(enc))
		}
		rawShards[i] = enc[ManifestSize:end]
	}

	decoder, err := reedsolomon.New(k, p)
	if err != nil {
		return nil, fmt.Errorf("creating Reed-Solomon decoder: %w", err)
	}

	if err := decoder.Reconstruct(rawShards); err != nil {
		return nil, fmt.Errorf("reconstruction failed (too few shards): %w", err)
	}

	var buf bytes.Buffer
	if err := decoder.Join(&buf, rawShards, int(ref.OriginalSize)); err != nil {
		return nil, fmt.Errorf("joining data shards: %w", err)
	}

	return buf.Bytes(), nil
}
