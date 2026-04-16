package shard

/*
Stateless beacon discovery using CRC64 algebraic forced-match.

DeriveBtarget derives a 64-bit target from the master password using
HMAC-SHA256. AlignBeacon appends the unique 8-byte solution (via FindPadding)
to any data stream so that crc64.Checksum(aligned) == target. A parallel
scanner walks a directory tree computing CRC64 per file — any file that
matches the beacon is a candidate carrier belonging to this shard set.

False-positive rate per file: 1/2^64 ≈ 5.4×10^-20.
*/

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc64"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

/* DeriveBtarget derives the 64-bit CRC64 beacon target from the master
password using HMAC-SHA256. All carriers in a shard set are forced to this
checksum value via AlignBeacon. */
func DeriveBtarget(password string) uint64 {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("nightcloak-beacon-v1"))
	h := mac.Sum(nil)
	return binary.BigEndian.Uint64(h[:8])
}

/*
AlignBeacon returns data with a unique 8-byte suffix appended such that
crc64.Checksum(result, ecmaTable) == DeriveBtarget(password).
Deterministic: same data + same password always produces the same suffix.
*/
func AlignBeacon(data []byte, password string) []byte {
	current := crc64.Checksum(data, ecmaTable)
	target := DeriveBtarget(password)
	padding := FindPadding(current, target)
	out := make([]byte, len(data)+8)
	copy(out, data)
	copy(out[len(data):], padding[:])
	return out
}

/* VerifyBeacon reports whether crc64.Checksum(data) matches the beacon
derived from password. */
func VerifyBeacon(data []byte, password string) bool {
	return crc64.Checksum(data, ecmaTable) == DeriveBtarget(password)
}

// ScanResult holds a matched carrier file path and its raw content.
type ScanResult struct {
	Path    string
	Content []byte
}

/*
Scan walks root recursively and returns every regular file whose CRC64
checksum matches the beacon for the given password.

Processed by a goroutine pool bounded by runtime.NumCPU() to avoid file
descriptor exhaustion. Result order is not guaranteed.
*/
func Scan(root, password string) ([]ScanResult, error) {
	target := DeriveBtarget(password)

	type job struct{ path string }
	jobs := make(chan job, 512)
	results := make(chan ScanResult, 128)

	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				data, err := os.ReadFile(j.path)
				if err != nil {
					continue
				}
				if crc64.Checksum(data, ecmaTable) == target {
					results <- ScanResult{Path: j.path, Content: data}
				}
			}
		}()
	}

	// Producer + closer: walk the tree, feed workers, then signal done.
	var walkErr error
	go func() {
		walkErr = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			jobs <- job{path}
			return nil
		})
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var found []ScanResult
	for r := range results {
		found = append(found, r)
	}
	return found, walkErr
}
