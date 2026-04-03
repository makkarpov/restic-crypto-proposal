package crypto_bench

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"golang.org/x/crypto/blake2b"
)

var (
	// 1 MiB input block.
	block1MiB = func() []byte {
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = byte(i)
		}
		return buf
	}()

	sha256Sink  [32]byte
	blake2bSink [64]byte
)

func BenchmarkHash1MiB(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(int64(len(block1MiB)))

	b.Run("SHA-256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sha256Sink = sha256.Sum256(block1MiB)
		}
	})

	b.Run("SHA-512", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			blake2bSink = sha512.Sum512(block1MiB)
		}
	})

	b.Run("BLAKE2b-512", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			blake2bSink = blake2b.Sum512(block1MiB)
		}
	})
}

