package shard

import (
	"hash/crc64"
	"math/rand"
	"testing"
)

var tab = crc64.MakeTable(crc64.ECMA)

// TestFindPadding_RandomTargets is the primary correctness proof.
// 10,000 random (data, target) pairs — each must pass with zero tolerance.
func TestFindPadding_RandomTargets(t *testing.T) {
	rng := rand.New(rand.NewSource(0xdeadbeefcafe))
	const iterations = 10_000

	for i := 0; i < iterations; i++ {
		data := make([]byte, rng.Intn(512)+1)
		rng.Read(data)
		target := rng.Uint64()

		currentCRC := crc64.Checksum(data, tab)
		padding := FindPadding(currentCRC, target)

		got := crc64.Checksum(append(data, padding[:]...), tab)
		if got != target {
			t.Fatalf("iter %d: got %016x, want %016x\n  data len=%d currentCRC=%016x",
				i, got, target, len(data), currentCRC)
		}
	}
	t.Logf("%d/%d passed (zero failures)", iterations, iterations)
}

// TestFindPadding_ZeroTarget forces CRC to zero.
func TestFindPadding_ZeroTarget(t *testing.T) {
	data := []byte("NightCloak beacon alignment test")
	currentCRC := crc64.Checksum(data, tab)
	padding := FindPadding(currentCRC, 0)
	got := crc64.Checksum(append(data, padding[:]...), tab)
	if got != 0 {
		t.Errorf("got %016x, want 0000000000000000", got)
	}
}

// TestFindPadding_EmptyData verifies the case where data is empty —
// the padding alone must produce the target CRC.
func TestFindPadding_EmptyData(t *testing.T) {
	const target = uint64(0xDEADBEEFCAFEBABE)
	currentCRC := crc64.Checksum(nil, tab)
	padding := FindPadding(currentCRC, target)
	got := crc64.Checksum(padding[:], tab)
	if got != target {
		t.Errorf("got %016x, want %016x", got, target)
	}
}

// TestFindPadding_Deterministic verifies the map is a pure function.
func TestFindPadding_Deterministic(t *testing.T) {
	data := []byte("determinism check")
	target := uint64(0x1234567890ABCDEF)
	c := crc64.Checksum(data, tab)
	p1 := FindPadding(c, target)
	p2 := FindPadding(c, target)
	if p1 != p2 {
		t.Error("FindPadding returned different results for identical inputs")
	}
}

// TestFindPadding_Uniqueness verifies that different targets produce different padding.
func TestFindPadding_Uniqueness(t *testing.T) {
	data := []byte("uniqueness test")
	c := crc64.Checksum(data, tab)
	p1 := FindPadding(c, 0xAAAAAAAAAAAAAAAA)
	p2 := FindPadding(c, 0xBBBBBBBBBBBBBBBB)
	if p1 == p2 {
		t.Error("different targets produced identical padding — bijection violated")
	}
}

// TestCombineCRC64 verifies the combine function against direct computation.
func TestCombineCRC64(t *testing.T) {
	cases := []struct{ a, b string }{
		{"hello", "world"},
		{"", "nonempty"},
		{"nonempty", ""},
		{"The quick brown fox", " jumps over the lazy dog"},
		{"NightCloak", "v0.9.0"},
		{"single", "x"},
	}
	for _, tc := range cases {
		want := crc64.Checksum([]byte(tc.a+tc.b), tab)
		c1 := crc64.Checksum([]byte(tc.a), tab)
		c2 := crc64.Checksum([]byte(tc.b), tab)
		got := CombineCRC64(c1, c2, int64(len(tc.b)))
		if got != want {
			t.Errorf("CombineCRC64(%q, %q): got %016x, want %016x", tc.a, tc.b, got, want)
		}
	}
}

// TestCombineCRC64_LargeOffset verifies matrix squaring correctness for large B.
func TestCombineCRC64_LargeOffset(t *testing.T) {
	b := make([]byte, 100_000)
	for i := range b {
		b[i] = byte(i * 7)
	}
	a := []byte("prefix")
	want := crc64.Checksum(append(a, b...), tab)
	c1 := crc64.Checksum(a, tab)
	c2 := crc64.Checksum(b, tab)
	got := CombineCRC64(c1, c2, int64(len(b)))
	if got != want {
		t.Errorf("large offset: got %016x, want %016x", got, want)
	}
}

// TestDeriveBtarget verifies determinism and domain separation.
func TestDeriveBtarget(t *testing.T) {
	t1 := DeriveBtarget("secret1")
	t2 := DeriveBtarget("secret2")
	t3 := DeriveBtarget("secret1")
	if t1 == t2 {
		t.Error("different secrets produced the same beacon")
	}
	if t1 != t3 {
		t.Error("DeriveBtarget is not deterministic")
	}
}

// TestInverseMatrixCorrectness verifies M^{-1} * M = I over GF(2).
func TestInverseMatrixCorrectness(t *testing.T) {
	M := buildCRC64ForwardMatrix()
	Minv := crc64InvMatrix // precomputed at init

	// M_inv * M should equal the identity.
	product := mulGF2Matrices(Minv, M)
	identity := identityMatrix()
	for i := 0; i < 64; i++ {
		if product[i] != identity[i] {
			t.Errorf("row %d of M^{-1}*M = %016x, want %016x", i, product[i], identity[i])
		}
	}
}

// TestLinearity verifies the core property: rawCRC64(s, P) = rawCRC64(s, 0) XOR rawCRC64(0, P).
func TestLinearity(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		s := rng.Uint64()
		var p [8]byte
		rng.Read(p[:])
		var zeros [8]byte

		lhs := rawCRC64(s, p[:])
		rhs := rawCRC64(s, zeros[:]) ^ rawCRC64(0, p[:])
		if lhs != rhs {
			t.Fatalf("linearity violated at iter %d: lhs=%016x rhs=%016x", i, lhs, rhs)
		}
	}
}

func BenchmarkFindPadding(b *testing.B) {
	data := []byte("benchmark payload for nightcloak beacon alignment")
	c := crc64.Checksum(data, tab)
	target := uint64(0xABCDEF0123456789)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FindPadding(c, target)
	}
}

func BenchmarkCombineCRC64(b *testing.B) {
	c1 := uint64(0x1111111111111111)
	c2 := uint64(0x2222222222222222)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CombineCRC64(c1, c2, 1_000_000)
	}
}
