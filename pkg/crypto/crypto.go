package crypto

import (
	"bytes"
	"compress/flate"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// NonceSize is the byte length of the ChaCha20-Poly1305 nonce.
	// Must equal chacha20poly1305.NonceSize (12).
	NonceSize = chacha20poly1305.NonceSize

	// KeySize is the byte length of the derived encryption key.
	// Must equal chacha20poly1305.KeySize (32).
	KeySize = chacha20poly1305.KeySize

	// v2 wire format constants (Argon2id).
	v2SaltSize   = 16
	v2HeaderSize = len(v2Magic) + v2SaltSize + NonceSize

	// v1 wire format constants (PBKDF2 legacy, read-only).
	v1SaltSize       = 12
	v1HeaderSize     = v1SaltSize + NonceSize
	pbkdf2Iterations = 100_000

	// v3 wire format constants (Argon2id + optional compression + machine lock + random padding).
	// Header: magic(4) + flags(1) + salt(16) + nonce(12) = 33 bytes.
	v3HeaderSize     = 4 + 1 + v2SaltSize + NonceSize
	v3FlagCompressed = byte(0x01) // plaintext was DEFLATE-compressed before encryption
	v3FlagLocked     = byte(0x02) // key is bound to the encrypting machine's identity

	// maxPadding is the upper bound on random pad bytes added in v3 blobs.
	maxPadding = 512
)

// v2Magic is the 4-byte prefix that identifies a v2 (Argon2id) ciphertext blob.
// v1 blobs have no prefix and start directly with the 12-byte PBKDF2 salt.
var v2Magic = [4]byte{0x4E, 0x43, 0x02, 0x00} // "NC\x02\x00"

// v3Magic identifies a v3 blob (Argon2id + optional compression + machine lock + random padding).
var v3Magic = [4]byte{0x4E, 0x43, 0x03, 0x00} // "NC\x03\x00"

// Argon2id parameters (OWASP minimum: time=2, mem=19MB; we use stronger defaults).
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
)

/*
Wire formats:

v3 (Argon2id + optional compression + machine lock + random padding, current):
  [4B magic][1B flags][16B salt][12B nonce][N bytes CIPHERTEXT+POLY1305_TAG]
  flags bit0=compressed, bit1=locked
  plaintext layout: [2B pad_len big-endian][pad bytes][data]
  data = DEFLATE(plaintext) if compressed, else plaintext

v2 (Argon2id):
  [4B magic][16B salt][12B nonce][N bytes CIPHERTEXT+POLY1305_TAG]

v1 (PBKDF2, legacy, read-only):
  [12B salt][12B nonce][N bytes CIPHERTEXT+POLY1305_TAG]
*/

/*
Encrypt authenticates and encrypts plaintext using ChaCha20-Poly1305.
Key derivation: Argon2id with a random 16-byte salt (v2 wire format).
Each call generates a fresh salt and nonce.
*/
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, v2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	aead, err := newArgon2AEAD(password, salt)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, v2HeaderSize+len(plaintext)+aead.Overhead())
	out = append(out, v2Magic[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)

	return out, nil
}

/* Decrypt verifies and decrypts ciphertext produced by Encrypt or EncryptV3.
Accepts v3 (Argon2id + compression + padding), v2 (Argon2id), and v1 (PBKDF2 legacy). */
func Decrypt(ciphertext []byte, password string) ([]byte, error) {
	if isV3(ciphertext) {
		return decryptV3(ciphertext, password)
	}
	if isV2(ciphertext) {
		return decryptV2(ciphertext, password)
	}
	return decryptV1(ciphertext, password)
}

// isV2 returns true if the blob starts with the v2 magic prefix.
func isV2(b []byte) bool {
	if len(b) < len(v2Magic) {
		return false
	}
	return b[0] == v2Magic[0] && b[1] == v2Magic[1] && b[2] == v2Magic[2] && b[3] == v2Magic[3]
}

// decryptV2 handles the current Argon2id wire format.
func decryptV2(ciphertext []byte, password string) ([]byte, error) {
	minLen := v2HeaderSize + chacha20poly1305.Overhead
	if len(ciphertext) < minLen {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[len(v2Magic) : len(v2Magic)+v2SaltSize]
	nonce := ciphertext[len(v2Magic)+v2SaltSize : v2HeaderSize]
	sealed := ciphertext[v2HeaderSize:]

	aead, err := newArgon2AEAD(password, salt)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or tampered data): %w", err)
	}

	return plaintext, nil
}

// decryptV1 handles the legacy PBKDF2 wire format for backward compatibility.
func decryptV1(ciphertext []byte, password string) ([]byte, error) {
	minLen := v1HeaderSize + chacha20poly1305.Overhead
	if len(ciphertext) < minLen {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[:v1SaltSize]
	nonce := ciphertext[v1SaltSize:v1HeaderSize]
	sealed := ciphertext[v1HeaderSize:]

	aead, err := newPBKDF2AEAD(password, salt)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or tampered data): %w", err)
	}

	return plaintext, nil
}

// newArgon2AEAD derives a 256-bit key via Argon2id and returns a ChaCha20-Poly1305 AEAD.
func newArgon2AEAD(password string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	return aead, nil
}

// newPBKDF2AEAD derives a 256-bit key via PBKDF2-HMAC-SHA256 (legacy v1 support).
func newPBKDF2AEAD(password string, salt []byte) (cipher.AEAD, error) {
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, KeySize, sha256.New)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	return aead, nil
}

/*
EncryptV3 encrypts plaintext using the v3 wire format.

Always includes random padding (0-maxPadding bytes) to vary ciphertext size
and defeat size-based carrier anomaly detection. compress applies DEFLATE
before padding, only if it actually reduces size. lock binds the key to the
current machine's hardware identity so the blob cannot be decrypted elsewhere.
*/
func EncryptV3(plaintext []byte, password string, compress, lock bool) ([]byte, error) {
	// Optional compression — only applied when it reduces size.
	data := plaintext
	compressed := false
	if compress {
		c, err := compressFlate(plaintext)
		if err != nil {
			return nil, fmt.Errorf("compressing: %w", err)
		}
		if len(c) < len(plaintext) {
			data = c
			compressed = true
		}
	}

	// Random padding prepended to data: [2B pad_len big-endian][pad bytes].
	padLen := mrand.Intn(maxPadding + 1)
	pad := make([]byte, padLen)
	if _, err := io.ReadFull(rand.Reader, pad); err != nil {
		return nil, fmt.Errorf("generating padding: %w", err)
	}
	inner := make([]byte, 2+padLen+len(data))
	inner[0] = byte(padLen >> 8)
	inner[1] = byte(padLen)
	copy(inner[2:], pad)
	copy(inner[2+padLen:], data)

	salt := make([]byte, v2SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Mix machine identity into the password when locking.
	pw := password
	if lock {
		pw = password + "\x00" + machineID()
	}

	aead, err := newArgon2AEAD(pw, salt)
	if err != nil {
		return nil, err
	}

	var flags byte
	if compressed {
		flags |= v3FlagCompressed
	}
	if lock {
		flags |= v3FlagLocked
	}

	out := make([]byte, 0, v3HeaderSize+len(inner)+aead.Overhead())
	out = append(out, v3Magic[:]...)
	out = append(out, flags)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, inner, nil)
	return out, nil
}

// isV3 returns true if the blob starts with the v3 magic prefix.
func isV3(b []byte) bool {
	if len(b) < len(v3Magic) {
		return false
	}
	return b[0] == v3Magic[0] && b[1] == v3Magic[1] && b[2] == v3Magic[2] && b[3] == v3Magic[3]
}

// decryptV3 handles the v3 wire format.
func decryptV3(ciphertext []byte, password string) ([]byte, error) {
	if len(ciphertext) < v3HeaderSize+chacha20poly1305.Overhead {
		return nil, errors.New("ciphertext too short")
	}

	flags := ciphertext[4]
	salt := ciphertext[5 : 5+v2SaltSize]
	nonce := ciphertext[5+v2SaltSize : v3HeaderSize]
	sealed := ciphertext[v3HeaderSize:]

	pw := password
	if flags&v3FlagLocked != 0 {
		pw = password + "\x00" + machineID()
	}

	aead, err := newArgon2AEAD(pw, salt)
	if err != nil {
		return nil, err
	}

	inner, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password, tampered data, or wrong machine): %w", err)
	}

	// Strip padding.
	if len(inner) < 2 {
		return nil, errors.New("invalid v3 payload: too short for padding header")
	}
	padLen := int(inner[0])<<8 | int(inner[1])
	if 2+padLen > len(inner) {
		return nil, errors.New("invalid v3 payload: pad length exceeds data")
	}
	data := inner[2+padLen:]

	// Decompress if needed.
	if flags&v3FlagCompressed != 0 {
		data, err = decompressFlate(data)
		if err != nil {
			return nil, fmt.Errorf("decompressing: %w", err)
		}
	}

	return data, nil
}

// compressFlate compresses data using DEFLATE at best compression.
func compressFlate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompressFlate decompresses DEFLATE-compressed data.
func decompressFlate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	return io.ReadAll(r)
}
