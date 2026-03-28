package shard

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// Split / Join unit tests
// ---------------------------------------------------------------------------

func TestSplitJoin_RoundTrip(t *testing.T) {
	cases := []struct {
		name         string
		payloadSize  int
		dataShards   int
		parityShards int
	}{
		{"small 4+2", 256, 4, 2},
		{"medium 6+3", 4096, 6, 3},
		{"large 8+4", 1 << 20, 8, 4}, // 1MB
		{"minimal 2+1", 100, 2, 1},
		{"no parity 4+0", 512, 4, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := randomBytes(tc.payloadSize)
			shards, err := Split(payload, tc.dataShards, tc.parityShards, "testpass")
			if err != nil {
				t.Fatalf("Split: %v", err)
			}

			n := tc.dataShards + tc.parityShards
			if len(shards) != n {
				t.Fatalf("expected %d shards, got %d", n, len(shards))
			}

			recovered, err := Join(shards, "testpass")
			if err != nil {
				t.Fatalf("Join: %v", err)
			}

			if !bytes.Equal(recovered, payload) {
				t.Fatalf("recovered payload differs from original (sizes: %d vs %d)",
					len(recovered), len(payload))
			}
		})
	}
}

func TestJoin_WithMissingShards(t *testing.T) {
	// (4, 2) scheme: can lose any 2 shards.
	payload := randomBytes(32768)
	shards, err := Split(payload, 4, 2, "losstest")
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	// Erase 2 shards (the maximum tolerable for this scheme).
	lossCases := [][2]int{{0, 1}, {0, 5}, {3, 5}, {2, 4}}
	for _, loss := range lossCases {
		t.Run(fmt.Sprintf("lose shards %v", loss), func(t *testing.T) {
			available := make([][]byte, 6)
			copy(available, shards)
			available[loss[0]] = nil
			available[loss[1]] = nil

			recovered, err := Join(available, "losstest")
			if err != nil {
				t.Fatalf("Join with loss %v: %v", loss, err)
			}
			if !bytes.Equal(recovered, payload) {
				t.Fatalf("loss %v: recovered payload mismatch", loss)
			}
		})
	}
}

func TestJoin_TooManyLost(t *testing.T) {
	// (4, 2): losing 3 shards must fail.
	payload := randomBytes(1024)
	shards, _ := Split(payload, 4, 2, "pass")
	shards[0] = nil
	shards[1] = nil
	shards[2] = nil

	_, err := Join(shards, "pass")
	if err == nil {
		t.Error("expected error when too many shards are missing, got nil")
	}
}

func TestManifest_RoundTrip(t *testing.T) {
	payload := randomBytes(512)
	shards, err := Split(payload, 3, 1, "manifesttest")
	if err != nil {
		t.Fatalf("Split: %v", err)
	}

	for i, s := range shards {
		m, err := DecodeManifest(s)
		if err != nil {
			t.Fatalf("shard %d: DecodeManifest: %v", i, err)
		}
		if m.Magic != manifestMagic {
			t.Errorf("shard %d: bad magic %x", i, m.Magic)
		}
		if m.Version != manifestVersion {
			t.Errorf("shard %d: bad version %d", i, m.Version)
		}
		if int(m.ShardIndex) != i {
			t.Errorf("shard %d: index field = %d", i, m.ShardIndex)
		}
		if int(m.DataShards) != 3 || int(m.ParityShards) != 1 {
			t.Errorf("shard %d: wrong K/P: %d/%d", i, m.DataShards, m.ParityShards)
		}
		if m.OriginalSize != uint64(len(payload)) {
			t.Errorf("shard %d: OriginalSize %d != %d", i, m.OriginalSize, len(payload))
		}
	}
}

func TestManifest_AllShardsSharePayloadID(t *testing.T) {
	payload := randomBytes(1024)
	shards, _ := Split(payload, 4, 2, "idtest")

	var refID [32]byte
	for i, s := range shards {
		m, _ := DecodeManifest(s)
		if i == 0 {
			refID = m.PayloadID
		} else if m.PayloadID != refID {
			t.Errorf("shard %d PayloadID differs from shard 0", i)
		}
	}
}

func TestPayloadID_DiffersPerPayload(t *testing.T) {
	p1, _ := Split(randomBytes(512), 2, 1, "pass")
	p2, _ := Split(randomBytes(512), 2, 1, "pass")
	m1, _ := DecodeManifest(p1[0])
	m2, _ := DecodeManifest(p2[0])
	if m1.PayloadID == m2.PayloadID {
		t.Error("different payloads produced the same PayloadID")
	}
}

// ---------------------------------------------------------------------------
// Beacon unit tests
// ---------------------------------------------------------------------------

func TestAlignBeacon_VerifyBeacon(t *testing.T) {
	data := []byte("nightcloak beacon alignment test data")
	aligned := AlignBeacon(data, "beaconpass")
	if !VerifyBeacon(aligned, "beaconpass") {
		t.Error("VerifyBeacon failed on AlignBeacon output")
	}
	if VerifyBeacon(aligned, "wrongpass") {
		t.Error("VerifyBeacon passed with wrong password")
	}
	if VerifyBeacon(data, "beaconpass") {
		t.Error("VerifyBeacon passed on unaligned data (should be ~impossible)")
	}
}

func TestAlignBeacon_AppendOnly(t *testing.T) {
	data := []byte("original data must not be modified")
	aligned := AlignBeacon(data, "pass")

	if len(aligned) != len(data)+8 {
		t.Errorf("aligned length = %d, want %d", len(aligned), len(data)+8)
	}
	if !bytes.Equal(aligned[:len(data)], data) {
		t.Error("AlignBeacon modified the original data prefix")
	}
}

func TestDeriveBtarget_HMAC(t *testing.T) {
	// Verify that different passwords give different targets.
	t1 := DeriveBtarget("password1")
	t2 := DeriveBtarget("password2")
	if t1 == t2 {
		t.Error("different passwords produced the same beacon target")
	}
	// Verify determinism.
	if DeriveBtarget("password1") != t1 {
		t.Error("DeriveBtarget is not deterministic")
	}
}

// ---------------------------------------------------------------------------
// Integration: Split → AlignBeacon → Scan → Join
// ---------------------------------------------------------------------------

// TestPipeline_SplitBeaconScanJoin is the full end-to-end proof:
//
//  1. Split 512KB random payload into (4, 2) shards.
//  2. Align each shard's CRC64 to the beacon derived from the password.
//  3. Write the 6 aligned shard files to a temp directory (with decoys).
//  4. Scan the directory — exactly 6 files must match the beacon.
//  5. Sort by shard index, reconstruct via Join.
//  6. Assert recovered payload == original.
//  7. Repeat with 2 shards removed to verify tolerance.
func TestPipeline_SplitBeaconScanJoin(t *testing.T) {
	const (
		payloadSize  = 512 * 1024
		dataShards   = 4
		parityShards = 2
		password     = "nightcloak-v0.9.0-rc1"
	)

	payload := randomBytes(payloadSize)

	// Step 1: Split.
	shards, err := Split(payload, dataShards, parityShards, password)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	n := dataShards + parityShards

	// Step 2 & 3: Align beacons and write to temp directory with decoys.
	dir := t.TempDir()

	for i, shard := range shards {
		aligned := AlignBeacon(shard, password)
		path := filepath.Join(dir, fmt.Sprintf("shard_%02d.bin", i))
		if err := os.WriteFile(path, aligned, 0o644); err != nil {
			t.Fatalf("writing shard %d: %v", i, err)
		}
	}

	// Write 10 decoy files with random content (should not match beacon).
	for i := 0; i < 10; i++ {
		decoy := randomBytes(4096)
		path := filepath.Join(dir, fmt.Sprintf("decoy_%02d.bin", i))
		_ = os.WriteFile(path, decoy, 0o644)
	}

	// Step 4: Scan.
	found, err := Scan(dir, password)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(found) != n {
		t.Fatalf("Scan found %d files, expected %d", len(found), n)
	}

	// Step 5: Arrange by shard index and join.
	encodedShards := make([][]byte, n)
	for _, r := range found {
		m, err := DecodeManifest(r.Content)
		if err != nil {
			t.Fatalf("DecodeManifest on scanned file %s: %v", r.Path, err)
		}
		encodedShards[m.ShardIndex] = r.Content
	}

	// Step 6: Join and verify.
	recovered, err := Join(encodedShards, password)
	if err != nil {
		t.Fatalf("Join (all shards): %v", err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Fatalf("full recovery: payload mismatch (got %d bytes, want %d)", len(recovered), len(payload))
	}
	t.Logf("Full recovery: OK (%d bytes)", len(recovered))

	// Step 7: Remove 2 shards (maximum loss for a 4+2 scheme).
	encodedShards[1] = nil
	encodedShards[4] = nil

	recovered2, err := Join(encodedShards, password)
	if err != nil {
		t.Fatalf("Join (2 shards lost): %v", err)
	}
	if !bytes.Equal(recovered2, payload) {
		t.Fatalf("partial recovery: payload mismatch")
	}
	t.Logf("Recovery with 2/%d shards lost: OK", n)
}

// TestPipeline_ScanIsolation verifies that shards from set A are not returned
// when scanning for set B (different password → different beacon → no match).
func TestPipeline_ScanIsolation(t *testing.T) {
	dir := t.TempDir()

	// Write 4 shards aligned to password A.
	shardsA, _ := Split(randomBytes(1024), 2, 2, "passwordA")
	for i, s := range shardsA {
		aligned := AlignBeacon(s, "passwordA")
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("a_%d.bin", i)), aligned, 0o644)
	}

	// Scan for password B — should find nothing.
	found, _ := Scan(dir, "passwordB")
	if len(found) != 0 {
		t.Errorf("scan for password B found %d files from password A set", len(found))
	}
}

// TestJoin_ShardOrderIndependent verifies Join works regardless of the order
// in which the caller populates the encodedShards slice.
func TestJoin_ShardOrderIndependent(t *testing.T) {
	payload := randomBytes(2048)
	shards, _ := Split(payload, 3, 2, "ordertest")
	n := len(shards)

	// Shuffle the order of available shards, then reassemble by index.
	shuffled := make([][]byte, n)
	copy(shuffled, shards)
	rand.Shuffle(n, func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	// Re-index by manifest field.
	ordered := make([][]byte, n)
	for _, s := range shuffled {
		m, _ := DecodeManifest(s)
		ordered[m.ShardIndex] = s
	}

	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] == nil {
			return false
		}
		if ordered[j] == nil {
			return true
		}
		mi, _ := DecodeManifest(ordered[i])
		mj, _ := DecodeManifest(ordered[j])
		return mi.ShardIndex < mj.ShardIndex
	})

	recovered, err := Join(ordered, "ordertest")
	if err != nil {
		t.Fatalf("Join: %v", err)
	}
	if !bytes.Equal(recovered, payload) {
		t.Error("shuffled-then-reindexed Join produced wrong payload")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
