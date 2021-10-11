package ifcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type HashAlgorithm string

const (
	HashNone   HashAlgorithm = "none"
	HashSha256 HashAlgorithm = "sha256"
	HashSha512 HashAlgorithm = "sha512"
	HashHMac   HashAlgorithm = "hmac"
)

// GetHasher returns the hash algorithm for the type.
//
// If _HashAlgorithmNone_ nil is returned.
//
// .Requesting a SHA256
// [source,go]
// ----
// sha256 := HashSha256.GetHasher()
// ----
func (alg HashAlgorithm) GetHasher() hash.Hash {

	switch alg {
	case HashNone:
		return nil
	case HashSha256:
		return sha256.New()
	case HashSha512:
		return sha512.New()
	}

	panic(fmt.Sprintf("not valid hasher alg: %s", alg))

}

// GetHasher returns the hash algorithm for the type.
//
// If _HashAlgorithmNone_ nil is returned.
//
// Parent is used when the current hash algorithm relies on a another.
//
// .Requesting a SHA256 HMAC
// [source,go]
// ----
// hmacSha256 := HashHMac.GetHasher(key, HashSha256.GetHasher())
// ----
func (alg HashAlgorithm) GetHasherWithKey(key []byte, parent hash.Hash) hash.Hash {

	switch alg {
	case HashNone:
		return nil
	case HashSha256:
		return sha256.New()
	case HashSha512:
		return sha512.New()
	case HashHMac:
		return hmac.New(
			func() hash.Hash { return parent }, key,
		)
	}

	panic(fmt.Sprintf("not valid hasher alg: %s", alg))

}

// Digester is capable of producing a digest with or without a key.
type Digester interface {
	// Digest will generate digest using the `hash.Hash`, optional _key_
	// on the _msg_ and return the digest.
	//
	// NOTE: Key is only needed when a hash algorithm needs a key, otherwise
	// set it to nil.
	//
	// The `HashAlgorithm` is interpreted in sequential order.
	//
	// .Example Multi Hash Digest
	// [source,go]
	// ----
	// hmacSha256Digester := NewDigester().Digest(key, msg, HashSha256, HashHMac)
	// ----
	Digest(key, msg []byte, h ...HashAlgorithm) ([]byte, error)
}
