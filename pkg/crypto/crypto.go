package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// SaltSize is the byte length of the PBKDF2 salt.
	SaltSize = 12

	// NonceSize is the byte length of the ChaCha20-Poly1305 nonce.
	// Must equal chacha20poly1305.NonceSize (12).
	NonceSize = chacha20poly1305.NonceSize

	// KeySize is the byte length of the derived encryption key.
	// Must equal chacha20poly1305.KeySize (32).
	KeySize = chacha20poly1305.KeySize

	// pbkdf2Iterations is the number of PBKDF2 rounds. 100k is the
	// current OWASP recommendation for HMAC-SHA256.
	pbkdf2Iterations = 100_000

	// headerSize is SaltSize + NonceSize, the fixed prefix before ciphertext.
	headerSize = SaltSize + NonceSize
)

// Wire format:
//
//	[12 bytes SALT][12 bytes NONCE][N bytes CIPHERTEXT+POLY1305_TAG]
//
// The AEAD tag (16 bytes) is appended to the ciphertext by Seal().
// Minimum valid ciphertext length is headerSize + poly1305 tag (16).

// Encrypt authenticates and encrypts plaintext using ChaCha20-Poly1305.
//
// Key derivation: PBKDF2-HMAC-SHA256 with a random 12-byte salt.
// Each call generates a fresh salt and nonce, so encrypting the same
// plaintext with the same password produces different output every time.
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	// Generate random salt and nonce.
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	aead, err := newAEAD(password, salt)
	if err != nil {
		return nil, err
	}

	// Allocate output: salt + nonce + ciphertext + tag.
	out := make([]byte, 0, headerSize+len(plaintext)+aead.Overhead())
	out = append(out, salt...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)

	return out, nil
}

// Decrypt verifies and decrypts ciphertext produced by Encrypt.
func Decrypt(ciphertext []byte, password string) ([]byte, error) {
	minLen := headerSize + chacha20poly1305.Overhead
	if len(ciphertext) < minLen {
		return nil, errors.New("ciphertext too short")
	}

	salt := ciphertext[:SaltSize]
	nonce := ciphertext[SaltSize:headerSize]
	sealed := ciphertext[headerSize:]

	aead, err := newAEAD(password, salt)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or tampered data): %w", err)
	}

	return plaintext, nil
}

// newAEAD derives a 256-bit key from password+salt and returns a
// ChaCha20-Poly1305 AEAD instance.
func newAEAD(password string, salt []byte) (cipher.AEAD, error) {
	key := pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, KeySize, sha256.New)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	return aead, nil
}
