package gocrypto

import (
	"fmt"

	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
)

// KeyBase implements most of the `ifcrypto.Key` interface.
//
// This is used to derive from and implement the key specific
// functions.
type KeyBase struct {
	id      string
	usage   []ifcrypto.KeyUsage
	chiper  []ifcrypto.Chipher
	keyType ifcrypto.KeyType
	keySize int
}

// GetID returns a id of the key.
//
// This is always specific of the backing _KMS_ system. For example, in _AWS_ this is a _ARN_ to
// a key in the _KMS_.
func (b *KeyBase) GetID() string {
	return b.id
}

// GetKeyUsage gets the keys usage. Some keys may have multiple usages.
func (b *KeyBase) GetKeyUsage() []ifcrypto.KeyUsage {
	return b.usage
}

// GetKeyType returns this keys `KeyType`.
func (b *KeyBase) GetKeyType() ifcrypto.KeyType {
	return b.keyType
}

// GetSupportedChiphers returns all the chipers that the key be used with.
func (b *KeyBase) GetSupportedChiphers() []ifcrypto.Chipher {
	return b.chiper
}

// CanSign checks if the current _Key_ may participate in _alg_ `SignAlgorithm` to do sign operations with.
func (b *KeyBase) CanSign(alg ifcrypto.SignAlgorithm) bool {

	if !b.HasUsage(ifcrypto.KeyUsageVerify) {
		return false
	}

	return b.matchSignAlgForKey(alg)

}

// CanVerify checks if the current _Key_ may participate in _alg_ `SignAlgorithm` to do verify on
func (b *KeyBase) CanVerify(alg ifcrypto.SignAlgorithm) bool {

	if !b.HasUsage(ifcrypto.KeyUsageVerify) {
		return false
	}

	return b.matchSignAlgForKey(alg)
}

// GetKeySize returns the number of bits of the key
func (b *KeyBase) GetKeySize() int {
	return b.keySize
}

// HasUsage checks if the _b_ do have the _u_ `ifcrypto.KeyUsage` support.
func (b *KeyBase) HasUsage(u ifcrypto.KeyUsage) bool {

	for i := range b.usage {

		if b.usage[i] == u {
			return true
		}

	}

	return false

}

// matchSignAlgForKey will ensure that the _alg_ do match the `ifcore.KeyType`
// for this _b_.
func (b *KeyBase) matchSignAlgForKey(alg ifcrypto.SignAlgorithm) bool {

	switch alg {
	case ifcrypto.SignAlgorithmRsaPssSha256,
		ifcrypto.SignAlgorithmRsaPssSha384,
		ifcrypto.SignAlgorithmRsaPssSha512,
		ifcrypto.SignAlgorithmRsaPkcs1V15Sha256,
		ifcrypto.SignAlgorithmRsaPkcs1V15Sha384,
		ifcrypto.SignAlgorithmRsaPkcs1V15Sha512:

		return b.keyType == ifcrypto.KeyTypeRsa

	case ifcrypto.SignAlgorithmEcdSha256,
		ifcrypto.SignAlgorithmEcdSha384,
		ifcrypto.SignAlgorithmEcdSha512:

		return b.keyType == ifcrypto.KeyTypeEccNistP ||
			b.keyType == ifcrypto.KeyTypeEccSecgP256k1
	}

	panic(
		fmt.Sprintf("can not handle SignAlgorithm: %s", alg),
	)

}
