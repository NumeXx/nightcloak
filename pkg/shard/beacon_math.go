// Package shard implements the CRC64 algebraic primitives for the
// NightCloak stateless beacon discovery system.
//
// Core insight: CRC64/ECMA is a GF(2)-linear map over its input data.
// This means the map L: P → rawCRC64(0, P) for an 8-byte input P is a
// bijection on GF(2)^64. Its inverse M^{-1} (precomputed at init) lets us
// find the unique 8-byte appendage that forces any file's CRC64 to a
// predetermined target value derived from the master secret.
//
// Reference: Stigge, Plötz, Müller, Redlich — "Reversing CRC — Theory and
// Practice." HU Berlin, SAR-PR-2006-05.
package shard

import (
	"encoding/binary"
	"hash/crc64"
	"math/bits"
)

var ecmaTable = crc64.MakeTable(crc64.ECMA)

// ---------------------------------------------------------------------------
// Raw CRC64 (no initial/final XOR)
// ---------------------------------------------------------------------------

// rawCRC64 runs the CRC64/ECMA update loop starting from state, processing
// each byte as: state = table[byte(state)^b] ^ (state >> 8).
//
// Unlike crc64.Checksum, this does NOT apply the initial ^state or final
// ^state inversion that Go's implementation adds. It is the bare GF(2)
// polynomial step used for all algebraic derivations below.
func rawCRC64(state uint64, data []byte) uint64 {
	for _, b := range data {
		state = ecmaTable[byte(state)^b] ^ (state >> 8)
	}
	return state
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// FindPadding returns the unique 8-byte sequence P such that:
//
//	crc64.Checksum(append(data, P[:]...), ecmaTable) == targetCRC
//
// given currentCRC = crc64.Checksum(data, ecmaTable).
//
// Algorithm: CRC64 over exactly 8 bytes is a GF(2)-linear bijection on
// {0,1}^64. We precompute its 64×64 GF(2) inverse matrix M^{-1} at init
// time and apply it here in O(64) — a single matrix-vector product.
// No search, no approximation, no allocation.
func FindPadding(currentCRC, targetCRC uint64) [8]byte {
	// Go's crc64.Checksum convention:
	//   Checksum(D) = ^rawCRC64(^0, D)
	//   Internal state after D = ^Checksum(D) = rawCRC64(^0, D)
	//
	// We need: Checksum(data || P) = targetCRC
	//   → rawCRC64(^currentCRC, P) = ^targetCRC
	//
	// Linearity: rawCRC64(s, P) = rawCRC64(s, zeros8) XOR rawCRC64(0, P)
	//   → rawCRC64(0, P) = ^targetCRC XOR rawCRC64(^currentCRC, zeros8)

	var zeros8 [8]byte
	adj := rawCRC64(^currentCRC, zeros8[:])
	needed := (^targetCRC) ^ adj

	// Solve the linear system L(P) = needed over GF(2).
	pBits := gf2MatVec(crc64InvMatrix, needed)

	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], pBits)
	return out
}

// CombineCRC64 returns the CRC64 of the concatenation A||B given the
// individual checksums and the byte length of B.
//
//	CombineCRC64(crc64.Checksum(a, t), crc64.Checksum(b, t), int64(len(b)))
//	  == crc64.Checksum(append(a, b...), t)
//
// Uses O(64·log(len2)) GF(2) matrix squaring — O(1) in practice since
// len2 is bounded by 63 squaring steps for any 64-bit length.
func CombineCRC64(crc1, crc2 uint64, len2 int64) uint64 {
	// rawCRC64(^crc1, B) = rawCRC64(^crc1, zeros(len2)) XOR rawCRC64(0, B)
	//
	// rawCRC64(0, B) via linearity:
	//   rawCRC64(^0, B) = rawCRC64(^0, zeros(len2)) XOR rawCRC64(0, B)
	//   → rawCRC64(0, B) = rawCRC64(^0, B) XOR rawCRC64(^0, zeros(len2))
	//                    = ^crc2           XOR shiftState(^0, len2)
	//
	// Checksum(A||B) = ^rawCRC64(^crc1, B)
	//               = ^(shiftState(^crc1, len2) XOR ^crc2 XOR shiftState(^0, len2))
	s1 := shiftState(^crc1, len2)
	s0 := shiftState(^uint64(0), len2)
	return ^(s1 ^ (^crc2) ^ s0)
}

// ---------------------------------------------------------------------------
// Precomputed inverse of the CRC64 8-byte forward map (init-time)
// ---------------------------------------------------------------------------

var crc64InvMatrix [64]uint64

func init() {
	crc64InvMatrix = invertGF2Matrix(buildCRC64ForwardMatrix())
}

// buildCRC64ForwardMatrix builds the 64×64 GF(2) matrix of the map
// L: P → rawCRC64(0, P) where P is 8 bytes packed as a little-endian uint64.
//
// Column j is L(e_j) where e_j has only bit j set. We transpose into
// row-major form for efficient gf2MatVec application.
func buildCRC64ForwardMatrix() [64]uint64 {
	var M [64]uint64 // M[i] = row i as a bitmask over 64 columns
	var buf [8]byte
	for j := 0; j < 64; j++ {
		buf = [8]byte{}
		buf[j/8] = 1 << uint(j%8)
		col := rawCRC64(0, buf[:])
		for i := 0; i < 64; i++ {
			if (col>>uint(i))&1 == 1 {
				M[i] |= 1 << uint(j)
			}
		}
	}
	return M
}

// invertGF2Matrix inverts a 64×64 GF(2) matrix via Gauss-Jordan elimination.
// Panics on singular input — impossible for a valid CRC64 polynomial.
func invertGF2Matrix(M [64]uint64) [64]uint64 {
	var a, inv [64]uint64
	copy(a[:], M[:])
	for i := range inv {
		inv[i] = 1 << uint(i)
	}

	for col := 0; col < 64; col++ {
		// Find pivot row: first row with bit col set.
		pivot := -1
		for row := col; row < 64; row++ {
			if (a[row]>>uint(col))&1 == 1 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			panic("CRC64 forward matrix is singular — invalid polynomial")
		}
		a[col], a[pivot] = a[pivot], a[col]
		inv[col], inv[pivot] = inv[pivot], inv[col]

		// Eliminate all other rows with a 1 in this column.
		for row := 0; row < 64; row++ {
			if row != col && (a[row]>>uint(col))&1 == 1 {
				a[row] ^= a[col]
				inv[row] ^= inv[col]
			}
		}
	}
	return inv
}

// gf2MatVec computes M·v over GF(2): result[i] = parity(M[i] AND v).
func gf2MatVec(M [64]uint64, v uint64) uint64 {
	var r uint64
	for i := 0; i < 64; i++ {
		if bits.OnesCount64(M[i]&v)&1 == 1 {
			r |= 1 << uint(i)
		}
	}
	return r
}

// ---------------------------------------------------------------------------
// Matrix squaring for CombineCRC64
// ---------------------------------------------------------------------------

// shiftState returns rawCRC64(state, zeros(n)) using binary exponentiation
// of the single-zero-byte transformation matrix. O(64·log n).
func shiftState(state uint64, n int64) uint64 {
	if n == 0 {
		return state
	}
	return gf2MatVec(buildShiftMatrix(n), state)
}

// buildShiftMatrix returns the GF(2) matrix for "process n zero bytes",
// computed as M1^n via repeated squaring of the one-byte matrix M1.
func buildShiftMatrix(n int64) [64]uint64 {
	result := identityMatrix()
	base := oneByteZeroMatrix()
	for n > 0 {
		if n&1 == 1 {
			result = mulGF2Matrices(result, base)
		}
		base = mulGF2Matrices(base, base)
		n >>= 1
	}
	return result
}

// oneByteZeroMatrix returns the 64×64 GF(2) matrix M1 such that
// M1·state = rawCRC64(state, [0x00]).
//
// For byte = 0: state' = table[state & 0xFF] ^ (state >> 8).
// By CRC linearity (table[a^b] = table[a]^table[b], table[0]=0):
//   state' = table[state & 0xFF] ^ (state >> 8)
// Column j of M1:
//   j < 8:  table[1<<j]          (low byte bit, zero upper contribution)
//   j >= 8: 1 << (j-8)           (upper bits just shift right by 8)
func oneByteZeroMatrix() [64]uint64 {
	var M [64]uint64
	for j := 0; j < 64; j++ {
		var col uint64
		if j < 8 {
			col = ecmaTable[1<<uint(j)]
		} else {
			col = 1 << uint(j-8)
		}
		for i := 0; i < 64; i++ {
			if (col>>uint(i))&1 == 1 {
				M[i] |= 1 << uint(j)
			}
		}
	}
	return M
}

func identityMatrix() [64]uint64 {
	var m [64]uint64
	for i := range m {
		m[i] = 1 << uint(i)
	}
	return m
}

// mulGF2Matrices multiplies two 64×64 GF(2) matrices.
// Transposes B first for cache-local row·row dot products.
func mulGF2Matrices(A, B [64]uint64) [64]uint64 {
	var Bt [64]uint64
	for i := 0; i < 64; i++ {
		for j := 0; j < 64; j++ {
			if (B[i]>>uint(j))&1 == 1 {
				Bt[j] |= 1 << uint(i)
			}
		}
	}
	var C [64]uint64
	for i := 0; i < 64; i++ {
		for j := 0; j < 64; j++ {
			if bits.OnesCount64(A[i]&Bt[j])&1 == 1 {
				C[i] |= 1 << uint(j)
			}
		}
	}
	return C
}
