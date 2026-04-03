package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

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
)

// v2Magic is the 4-byte prefix that identifies a v2 (Argon2id) ciphertext blob.
// v1 blobs have no prefix and start directly with the 12-byte PBKDF2 salt.
var v2Magic = [4]byte{0x4E, 0x43, 0x02, 0x00} // "NC\x02\x00"

// Argon2id parameters (OWASP minimum: time=2, mem=19MB; we use stronger defaults).
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
)

// Wire formats:
//
// v2 (Argon2id, current):
//
//	[4B magic][16B salt][12B nonce][N bytes CIPHERTEXT+POLY1305_TAG]
//
// v1 (PBKDF2, legacy, read-only):
//
//	[12B salt][12B nonce][N bytes CIPHERTEXT+POLY1305_TAG]

// Encrypt authenticates and encrypts plaintext using ChaCha20-Poly1305.
//
// Key derivation: Argon2id with a random 16-byte salt (v2 wire format).
// Each call generates a fresh salt and nonce.
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

// Decrypt verifies and decrypts ciphertext produced by Encrypt.
// Accepts both v2 (Argon2id) and v1 (PBKDF2 legacy) wire formats.
func Decrypt(ciphertext []byte, password string) ([]byte, error) {
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
