package crypto_bench

import (
	"encoding/binary"
	"testing"
)

func BenchmarkEncrypt1MiB(b *testing.B) {
	key, err := NewRandomKey()
	if err != nil {
		b.Fatalf("NewRandomKey: %v", err)
	}

	plaintext := make([]byte, 1<<20) // 1 MiB
	blob := make([]byte, 0, len(plaintext)+BlobOverhead)

	// Use a deterministic counter nonce in the timed loop so the result reflects
	// encryption+MAC throughput, not crypto/rand overhead.
	var nonce [NonceSize]byte
	nonce[0] = 1 // non-zero; restic rejects an all-zero nonce

	b.SetBytes(int64(len(plaintext)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Unique nonce per iteration.
		binary.LittleEndian.PutUint64(nonce[8:], uint64(i+1))

		blob = blob[:0]
		blob = key.EncryptBlob(blob, nonce[:], plaintext)
	}

	_ = blob
}
