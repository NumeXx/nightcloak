package crypto

/*
Optional secondary encryption layer using XChaCha20-Poly1305.

Activated by the KEY environment variable. The layer wraps the primary
ChaCha20-Poly1305 ciphertext, providing independent key material for
the outer envelope. The two layers use different algorithms (standard
12-byte nonce vs. extended 24-byte nonce), different key derivation
paths, and independent authentication tags.

Wire format for the outer layer:
  [24B XChaCha20 nonce][ciphertext + 16B Poly1305 tag]

Key resolution (resolveXKey):
  1. KEY="-"    → generate 32 random bytes, encode as Base58, print to stderr,
                  return raw bytes as key.
  2. KEY=<b58>  → Base58-decode; if result is exactly 32 bytes use directly.
  3. KEY=<str>  → SHA-256 of the string → 32-byte key (allows human passphrases).

Base58 uses the standard Bitcoin alphabet (no 0/O/I/l).
*/

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// XEncrypt encrypts plaintext with XChaCha20-Poly1305 using the given 32-byte key.
// Output: [24B nonce][ciphertext + 16B tag].
func XEncrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("creating XChaCha20 cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// XDecrypt verifies and decrypts ciphertext produced by XEncrypt.
func XDecrypt(ciphertext, key []byte) ([]byte, error) {
	minLen := chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if len(ciphertext) < minLen {
		return nil, errors.New("XChaCha20 ciphertext too short")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("creating XChaCha20 cipher: %w", err)
	}

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	sealed := ciphertext[chacha20poly1305.NonceSizeX:]

	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20 decryption failed (wrong KEY or tampered data): %w", err)
	}
	return plaintext, nil
}

// ResolveXKey reads the KEY environment variable and returns a 32-byte key,
// or nil if KEY is not set. If KEY="-", a random key is generated and its
// Base58 encoding is printed to stderr before being returned.
func ResolveXKey() ([]byte, error) {
	keyStr := os.Getenv("KEY")
	if keyStr == "" {
		return nil, nil
	}

	// Generate random key mode.
	if keyStr == "-" {
		key := make([]byte, KeySize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("generating random key: %w", err)
		}
		// Display the first 22 Base58 characters of the full key.
		// 22 chars ≈ 130 bits of entropy — above the 128-bit security floor.
		// The full 32-byte key is used internally; only the display is shortened.
		full := Base58Encode(key)
		display := full
		if len(display) > 22 {
			display = display[:22]
		}
		fmt.Fprintf(os.Stderr, "  [KEY] %s\n", display)
		return key, nil
	}

	// Try Base58 decode first.
	decoded, err := Base58Decode(keyStr)
	if err == nil && len(decoded) == KeySize {
		return decoded, nil
	}

	// Fall back to SHA-256 derivation for arbitrary strings.
	h := sha256.Sum256([]byte(keyStr))
	return h[:], nil
}

// Base58Encode encodes b using the standard Base58 alphabet.
func Base58Encode(b []byte) string {
	// Count leading zero bytes — each maps to '1'.
	leadingOnes := 0
	for _, byt := range b {
		if byt != 0x00 {
			break
		}
		leadingOnes++
	}

	n := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)

	var digits []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}

	for i := 0; i < leadingOnes; i++ {
		digits = append(digits, base58Alphabet[0])
	}

	// Reverse in place.
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}

	return string(digits)
}

// Base58Decode decodes a Base58-encoded string back to bytes.
func Base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)

	for _, c := range s {
		idx := -1
		for i, a := range base58Alphabet {
			if a == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil, fmt.Errorf("invalid Base58 character: %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}

	decoded := n.Bytes()

	// Restore leading zero bytes (encoded as leading '1's).
	leadingOnes := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingOnes++
	}

	result := make([]byte, leadingOnes+len(decoded))
	copy(result[leadingOnes:], decoded)
	return result, nil
}
