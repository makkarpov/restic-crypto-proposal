package crypto_bench

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	mathrand "math/rand/v2"
	"runtime"
	"testing"

	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

var (
	sinkPub    x25519.Key
	sinkShared x25519.Key
)

var sinkFinal [sha256.Size]byte

func BenchmarkX25519(b *testing.B) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	// Seed software RNG once from system random.
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	prng := mathrand.NewChaCha8(seed)

	// Static peer keypair, generated outside the timed region.
	var staticSK, staticPK x25519.Key
	if _, err := prng.Read(staticSK[:]); err != nil {
		b.Fatal(err)
	}
	x25519.KeyGen(&staticPK, &staticSK)

	var ephSK, ephPK, shared x25519.Key

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Ephemeral private key from software RNG.
		if _, err := prng.Read(ephSK[:]); err != nil {
			b.Fatal(err)
		}

		// Ephemeral public key.
		x25519.KeyGen(&ephPK, &ephSK)

		// ECDH(static public, ephemeral private).
		if ok := x25519.Shared(&shared, &ephSK, &staticPK); !ok {
			b.Fatal("unexpected low-order static public key")
		}
	}

	sinkPub = ephPK
	sinkShared = shared
}

func BenchmarkPQC(b *testing.B) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)

	// Seed software RNG once from system random.
	var seed [32]byte
	if _, err := cryptorand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	prng := mathrand.NewChaCha8(seed)

	// Static X25519 peer keypair, generated outside the timed region.
	var staticXSK, staticXPK x25519.Key
	if _, err := prng.Read(staticXSK[:]); err != nil {
		b.Fatal(err)
	}
	x25519.KeyGen(&staticXPK, &staticXSK)

	// Static ML-KEM-1024 recipient keypair, generated outside the timed region.
	staticKEMPK, _, err := mlkem1024.GenerateKeyPair(prng)
	if err != nil {
		b.Fatal(err)
	}

	var ephXSK, ephXPK, xshared x25519.Key
	var kemSeed [mlkem1024.EncapsulationSeedSize]byte
	var kemCT [mlkem1024.CiphertextSize]byte
	var kemShared [mlkem1024.SharedKeySize]byte
	var transcript [32 + mlkem1024.SharedKeySize]byte
	var final [sha256.Size]byte

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// X25519: ephemeral private key from software RNG.
		if _, err := prng.Read(ephXSK[:]); err != nil {
			b.Fatal(err)
		}

		// X25519: ephemeral public key.
		x25519.KeyGen(&ephXPK, &ephXSK)

		// X25519: ECDH(static public, ephemeral private).
		if ok := x25519.Shared(&xshared, &ephXSK, &staticXPK); !ok {
			b.Fatal("unexpected low-order static X25519 public key")
		}

		// ML-KEM-1024: per-encapsulation randomness from software RNG.
		if _, err := prng.Read(kemSeed[:]); err != nil {
			b.Fatal(err)
		}

		// ML-KEM-1024: encapsulate to the static public key.
		staticKEMPK.EncapsulateTo(kemCT[:], kemShared[:], kemSeed[:])

		// Final transcript secret = SHA256(x25519_secret || mlkem_secret).
		copy(transcript[:32], xshared[:])
		copy(transcript[32:], kemShared[:])
		final = sha256.Sum256(transcript[:])
	}

	sinkFinal = final
	_ = ephXPK // keeps the public-key derivation in the loop semantically obvious
	_ = kemCT  // keeps encapsulation ciphertext production in the loop semantically obvious
}
