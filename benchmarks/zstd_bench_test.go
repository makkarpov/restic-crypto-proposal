package crypto_bench

import (
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

var (
	zstdCompressedSink []byte
	zstdIterNsSink     int64
)

func BenchmarkZstdCompressSrcTar(b *testing.B) {
	src, err := os.ReadFile("src.tar")
	if err != nil {
		b.Fatalf("read src.tar: %v", err)
	}
	if len(src) == 0 {
		b.Fatal("src.tar is empty")
	}

	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		b.Fatalf("new zstd encoder: %v", err)
	}
	defer func() { _ = enc.Close() }()

	// Preallocate enough capacity to avoid repeated growth in the timed loop.
	dst := make([]byte, 0, enc.MaxEncodedSize(len(src)))

	var total time.Duration

	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()

		dst = enc.EncodeAll(src, dst[:0])

		elapsed := time.Since(start)
		total += elapsed

		// Prevent the compiler from optimizing the work away.
		zstdCompressedSink = dst
		zstdIterNsSink = elapsed.Nanoseconds()
	}

	// Redundant with the built-in ns/op, but kept as an explicit per-compression metric.
	b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "ns/compress")
	b.ReportMetric(float64(total.Microseconds())/float64(b.N), "us/compress")
	b.ReportMetric(float64(len(zstdCompressedSink)), "compressed_len")
}
