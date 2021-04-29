package ifcrypto

import "crypto"

// KeyUsage is the usage of a key.
//
// NOTE: Some keys may have multiple _KeyUsage_.
type KeyUsage string

const (
	// KeyUsageSign allows this key to sign a message
	KeyUsageSign KeyUsage = "sign"
	// KeyUsageVerify allows the key to verify / authenticate a message
	KeyUsageVerify KeyUsage = "verify"
	// KeyUsageDecrypt allows the key to decrypt a message
	KeyUsageDecrypt KeyUsage = "decrypt"
	// KeyUsageEncrypt allows the key do encrypt a message
	KeyUsageEncrypt KeyUsage = "encrypt"
)

// KeyType is the type of key
type KeyType string

const (
	KeyTypeRsa           KeyType = "rsa"
	KeyTypeEccNistP      KeyType = "ecc-nist-p"
	KeyTypeEccSecgP256k1 KeyType = "ecc-secg_p256K1"
	// KeyTypeSymmetric is a key to use for symmetric operations in contrast to all other
	// `KeyType` where those are asymmetric.
	KeyTypeSymmetric KeyType = "symmetric"
)

// KeySizes specifies which key sizes a `KeyType` may assume.
//
// If omitted, empty array, it is possibly unlimited.
var KeySizes = map[KeyType][]int{
	KeyTypeRsa:           {2048, 3072, 4096},
	KeyTypeEccNistP:      {256, 384, 521},
	KeyTypeEccSecgP256k1: {256},
	KeyTypeSymmetric:     {},
}

// SignAlgorithm specifies which type of signing algorithm being used to sign or verify.
type SignAlgorithm string

// Enum values for SignAlgorithm
const (
	SignAlgorithmRsaPssSha256      SignAlgorithm = "rsa-pss-sha256"
	SignAlgorithmRsaPssSha384      SignAlgorithm = "rsa-pss-sha384"
	SignAlgorithmRsaPssSha512      SignAlgorithm = "rsa-pss-sha512"
	SignAlgorithmRsaPkcs1V15Sha256 SignAlgorithm = "rsa-pkcs1-v1.5-sha256"
	SignAlgorithmRsaPkcs1V15Sha384 SignAlgorithm = "rsa-pkcs1-v1.5-sha384"
	SignAlgorithmRsaPkcs1V15Sha512 SignAlgorithm = "rsa-pkcs1-v1.5-sha512"
	SignAlgorithmEcdSha256         SignAlgorithm = "ecd-sha256"
	SignAlgorithmEcdSha384         SignAlgorithm = "ecd-sha384"
	SignAlgorithmEcdSha512         SignAlgorithm = "ecd-sha512"
)

// Key represents a single key.
//
// The key may or may not be present in memory, it may be within a hardware unit or in a service
// such as _AWS KMS_ and the `Key` instance is merely a info block.
type Key interface {
	// GetID returns a id of the key.
	//
	// This is always specific of the backing _KMS_ system. For example, in _AWS_ this is a _ARN_ to
	// a key in the _KMS_.
	GetID() string
	// GetKeyUsage gets the keys usage. Some keys may have multiple usages.
	GetKeyUsage() []KeyUsage
	// GetKeySize returns the number of bits of the key
	GetKeySize() int
	// GetKeyType returns this keys `KeyType`.
	GetKeyType() KeyType
	// CanSign checks if the current _Key_ may participate in _alg_ `SignAlgorithm` to do sign operations with.
	CanSign(alg SignAlgorithm) bool
	// CanVerify checks if the current _Key_ may participate in _alg_ `SignAlgorithm` to do verify on
	CanVerify(alg SignAlgorithm) bool
	// GetKey gets the underlying key, if any.
	//
	// Some keys are remote and not possible to fetch. In such situations the function returns a remote id,
	// most often the same as GetID() returns.
	GetKey() interface{}
	// IsSymmetric returns `true` if this is a `KeyTypeSymmetric`
	//
	// This is a convenience function instead of `GetKeyType`.
	IsSymmetric() bool
	// IsPrivate returns `true` if this is a `KeyType` other than `KeyTypeSymmetric` and is a private key.
	//
	// If `KeyTypeSymmetric` it will return `true` since all symmetric keys are considered as private.
	IsPrivate() bool
	// IsRemoteKey returns `true` if the key is not present in current process memory.
	//
	// Typically hardware units or remote services will not reveal their private key. In such case, this
	// method returns `true`. If present in memory such as a `*rsa.PrivateKey` it returns `false`.
	IsRemoteKey() bool
}

// PublicKey is a explicit public `Key`
type PublicKey interface {
	crypto.PublicKey
	Key
}

// PrivateKey is a explicit private `Key`
type PrivateKey interface {
	crypto.PrivateKey
	Key
}

// KeyPair contains a private and a public key.
//
// NOTE: Some properties may differ from the main private key and the public key.
// For example a private key may be configured to only sign a message, whereas the
// public key may be used only for verification.
type KeyPair interface {
	// Key - holds the private portion of this key.
	PrivateKey
	// GetPublic returns the public portion of the key
	GetPublic() PublicKey
}
