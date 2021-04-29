package gocrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"

	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/utils/cryptoutils"
)

// ECDSAPrivateKey implements the `ifcrypto.KeyPair` interface for a `*rsa.PrivateKey`.
type ECDSAPrivateKey struct {
	KeyBase
	key    *ecdsa.PrivateKey
	public *ECDSAPublicKey
}

// NewECDSAPrivateKeyFromKey creates a new `ECDSAPrivateKey`
//
// The public key portion derives the same usage as the private key
func NewECDSAPrivateKeyFromKey(
	id string,
	key *ecdsa.PrivateKey,
	usage ...ifcrypto.KeyUsage,
) *ECDSAPrivateKey {

	return &ECDSAPrivateKey{
		KeyBase: KeyBase{
			id:      id,
			keyType: ifcrypto.KeyTypeRsa,
			keySize: key.Params().BitSize,
			usage:   usage,
		},
		key:    key,
		public: NewECDSAPublicKeyFromKey(id, &key.PublicKey, usage...),
	}

}

// NewECDSAPrivateKey generates a new `ECDSAPrivateKey` using the `rand.Reader` as entropy.
func NewECDSAPrivateKey(id string, bits int, usage ...ifcrypto.KeyUsage) (*ECDSAPrivateKey, error) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return NewECDSAPrivateKeyFromKey(id, key, usage...), nil
}

// GetPublic returns the public portion of the key
func (r *ECDSAPrivateKey) GetPublic() ifcrypto.PublicKey {
	return r.public
}

// PEMWrite will write the key onto _w_.
//
// If private key, and _public_ is `true`, it will in addition write the public portion as well.
func (r *ECDSAPrivateKey) PEMWrite(w io.Writer, public bool) error {

	return cryptoutils.ECDSAPrivateKeyToPEM(w, r.key, public)

}

// GetKey gets the underlying key, if any.
//
// Some keys are remote and not possible to fetch. In such situations the function returns a remote id,
// most often the same as GetID() returns.
func (r *ECDSAPrivateKey) GetKey() interface{} {
	return r.key
}

// IsSymmetric returns `true` if this is a `KeyTypeSymmetric`
//
// This is a convenience function instead of `GetKeyType`.
func (r *ECDSAPrivateKey) IsSymmetric() bool {
	return false
}

// IsPrivate returns `true` if this is a `KeyType` other than `KeyTypeSymmetric` and is a private key.
//
// If `KeyTypeSymmetric` it will return `true` since all symmetric keys are considered as private.
func (r *ECDSAPrivateKey) IsPrivate() bool {
	return true
}

// IsRemoteKey returns `true` if the key is not present in current process memory.
//
// Typically hardware units or remote services will not reveal their private key. In such case, this
// method returns `true`. If present in memory such as a `*rsa.PrivateKey` it returns `false`.
func (r *ECDSAPrivateKey) IsRemoteKey() bool {
	return false
}

// ECDSAPublicKey implements the `ifcrypto.PublicKey` interface for `*rsa.PublicKey`
type ECDSAPublicKey struct {
	KeyBase
	key *ecdsa.PublicKey
}

// NewECDSAPublicKeyFromKey creates a instance based on a existing public key.
func NewECDSAPublicKeyFromKey(
	id string,
	key *ecdsa.PublicKey,
	usage ...ifcrypto.KeyUsage,
) *ECDSAPublicKey {

	return &ECDSAPublicKey{
		KeyBase: KeyBase{
			id:      id,
			keyType: ifcrypto.KeyTypeRsa,
			keySize: key.Params().BitSize,
			usage:   usage,
		},
		key: key,
	}

}

// PEMWrite will write the key onto _w_.
//
// Since this is a public key, it will ignore the _public_ parameter.
func (r *ECDSAPublicKey) PEMWrite(w io.Writer, public bool) error {

	return cryptoutils.ECDSAPublicKeyToPEM(w, r.key)

}

// GetKey gets the underlying key, if any.
//
// Some keys are remote and not possible to fetch. In such situations the function returns a remote id,
// most often the same as GetID() returns.
func (r *ECDSAPublicKey) GetKey() interface{} {
	return r.key
}

// IsSymmetric returns `true` if this is a `KeyTypeSymmetric`
//
// This is a convenience function instead of `GetKeyType`.
func (r *ECDSAPublicKey) IsSymmetric() bool {
	return false
}

// IsPrivate returns `true` if this is a `KeyType` other than `KeyTypeSymmetric` and is a private key.
//
// If `KeyTypeSymmetric` it will return `true` since all symmetric keys are considered as private.
func (r *ECDSAPublicKey) IsPrivate() bool {
	return true
}

// IsRemoteKey returns `true` if the key is not present in current process memory.
//
// Typically hardware units or remote services will not reveal their private key. In such case, this
// method returns `true`. If present in memory such as a `*rsa.PrivateKey` it returns `false`.
func (r *ECDSAPublicKey) IsRemoteKey() bool {
	return false
}
