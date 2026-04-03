package crypto_bench

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/poly1305"
)

const (
	EncryptionKeySize = 32 // AES-256
	MACAESKeySize     = 16 // AES-128 key used to derive Poly1305 nonce part
	MACRKeySize       = 16 // Poly1305 r
	NonceSize         = aes.BlockSize
	TagSize           = poly1305.TagSize
	BlobOverhead      = NonceSize + TagSize // IV || ... || MAC
)

var ErrUnauthenticated = errors.New("ciphertext verification failed")

type EncryptionKey [EncryptionKeySize]byte

type MACKey struct {
	K [MACAESKeySize]byte
	R [MACRKeySize]byte
}

type Key struct {
	EncryptionKey
	MACKey
}

func NewRandomKey() (*Key, error) {
	k := &Key{}

	if _, err := crand.Read(k.EncryptionKey[:]); err != nil {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	if _, err := crand.Read(k.MACKey.K[:]); err != nil {
		return nil, fmt.Errorf("read MAC AES key: %w", err)
	}
	if _, err := crand.Read(k.MACKey.R[:]); err != nil {
		return nil, fmt.Errorf("read MAC r key: %w", err)
	}

	return k, nil
}

func (k *Key) Valid() bool {
	return k.EncryptionKey.Valid() && k.MACKey.Valid()
}

func (k EncryptionKey) Valid() bool {
	for _, b := range k {
		if b != 0 {
			return true
		}
	}
	return false
}

func (m MACKey) Valid() bool {
	hasK := false
	for _, b := range m.K {
		if b != 0 {
			hasK = true
			break
		}
	}
	if !hasK {
		return false
	}

	for _, b := range m.R {
		if b != 0 {
			return true
		}
	}
	return false
}

// Seal returns CIPHERTEXT || MAC.
// The caller supplies the nonce separately, matching restic's internal AEAD-like API.
func (k *Key) Seal(dst, nonce, plaintext []byte) []byte {
	if !k.Valid() {
		panic("invalid key")
	}
	if len(nonce) != NonceSize {
		panic("incorrect nonce length")
	}
	if !validNonce(nonce) {
		panic("nonce is invalid")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)

	block, err := aes.NewCipher(k.EncryptionKey[:])
	if err != nil {
		panic(fmt.Sprintf("create AES cipher: %v", err))
	}

	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(out[:len(plaintext)], plaintext)

	tag := poly1305MAC(out[:len(plaintext)], nonce, &k.MACKey)
	copy(out[len(plaintext):], tag[:])

	return ret
}

// Open expects CIPHERTEXT || MAC.
func (k *Key) Open(dst, nonce, ciphertextAndTag []byte) ([]byte, error) {
	if !k.Valid() {
		return nil, errors.New("invalid key")
	}
	if len(nonce) != NonceSize {
		panic("incorrect nonce length")
	}
	if !validNonce(nonce) {
		return nil, errors.New("nonce is invalid")
	}
	if len(ciphertextAndTag) < TagSize {
		return nil, errors.New("ciphertext too short")
	}

	ctLen := len(ciphertextAndTag) - TagSize
	ct := ciphertextAndTag[:ctLen]
	tag := ciphertextAndTag[ctLen:]

	if !poly1305Verify(ct, nonce, &k.MACKey, tag) {
		return nil, ErrUnauthenticated
	}

	ret, out := sliceForAppend(dst, ctLen)

	block, err := aes.NewCipher(k.EncryptionKey[:])
	if err != nil {
		panic(fmt.Sprintf("create AES cipher: %v", err))
	}

	stream := cipher.NewCTR(block, nonce)
	stream.XORKeyStream(out, ct)

	return ret, nil
}

// EncryptBlob returns IV || CIPHERTEXT || MAC.
func (k *Key) EncryptBlob(dst, nonce, plaintext []byte) []byte {
	if len(nonce) != NonceSize {
		panic("incorrect nonce length")
	}

	dst = append(dst, nonce...)
	return k.Seal(dst, nonce, plaintext)
}

// DecryptBlob expects IV || CIPHERTEXT || MAC.
func (k *Key) DecryptBlob(dst, blob []byte) ([]byte, error) {
	if len(blob) < BlobOverhead {
		return nil, errors.New("blob too short")
	}

	nonce := blob[:NonceSize]
	ciphertextAndTag := blob[NonceSize:]
	return k.Open(dst, nonce, ciphertextAndTag)
}

func poly1305MAC(msg, nonce []byte, key *MACKey) [TagSize]byte {
	prepared := poly1305PrepareKey(nonce, key)

	var out [TagSize]byte
	poly1305.Sum(&out, msg, &prepared)
	return out
}

func poly1305Verify(msg, nonce []byte, key *MACKey, mac []byte) bool {
	prepared := poly1305PrepareKey(nonce, key)

	var tag [TagSize]byte
	copy(tag[:], mac)

	return poly1305.Verify(&tag, msg, &prepared)
}

// Poly1305 one-time key = r || AES_k(nonce)
func poly1305PrepareKey(nonce []byte, key *MACKey) [32]byte {
	var prepared [32]byte

	block, err := aes.NewCipher(key.K[:])
	if err != nil {
		panic(fmt.Sprintf("create Poly1305-AES key cipher: %v", err))
	}

	block.Encrypt(prepared[16:], nonce)
	copy(prepared[:16], key.R[:])

	return prepared
}

func validNonce(nonce []byte) bool {
	var sum byte
	for _, b := range nonce {
		sum |= b
	}
	return sum != 0
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	total := len(in) + n
	if cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return head, tail
}

