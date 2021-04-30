package gocrypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/utils/cryptoutils"
)

// RSAPrivateKey implements the `ifcrypto.KeyPair` interface for a `*rsa.PrivateKey`.
type RSAPrivateKey struct {
	KeyBase
	key    *rsa.PrivateKey
	public *RSAPublicKey
}

// NewRSAPrivateKeyFromKey creates a new `RSAPrivateKey`
//
// The public key portion derives the same usage as the private key
func NewRSAPrivateKeyFromKey(
	id string,
	key *rsa.PrivateKey,
	usage ...ifcrypto.KeyUsage,
) *RSAPrivateKey {

	return &RSAPrivateKey{
		KeyBase: KeyBase{
			id:      id,
			keyType: ifcrypto.KeyTypeRsa,
			keySize: key.Size(),
			usage:   usage,
			chiper:  []ifcrypto.Chipher{},
		},
		key:    key,
		public: NewRSAPublicKeyFromKey(id, &key.PublicKey, usage...),
	}

}

// NewRSAPrivateKeyFromPEM initializes a new `*rsa.PrivateKey` from the underlying _PEM_ block.
func NewRSAPrivateKeyFromPEM(
	block pem.Block,
	id string,
	usage ...ifcrypto.KeyUsage,
) (*RSAPrivateKey, error) {

	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)

		if err != nil {
			return nil, err
		}

		if rsakey, ok := key.(*rsa.PrivateKey); ok {

			return NewRSAPrivateKeyFromKey(id, rsakey, usage...), nil

		}

		return nil, fmt.Errorf("not a rsa.PrivateKey: %T", key)

	}

	if block.Type == "RSA PRIVATE KEY" {

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return NewRSAPrivateKeyFromKey(id, key, usage...), nil

	}

	return nil, fmt.Errorf("unsupported PEM block: %s", block.Type)

}

// NewRSAPrivateKey generates a new `RSAPrivateKey` using the `rand.Reader` as entropy.
func NewRSAPrivateKey(id string, bits int, usage ...ifcrypto.KeyUsage) (*RSAPrivateKey, error) {

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	return NewRSAPrivateKeyFromKey(id, key, usage...), nil
}

// Sign implements the `crypto.Signer` _interface_.If opts is a
// *PSSOptions then the PSS algorithm will be used, otherwise
// PKCS #1 v1.5 will be used.
func (r *RSAPrivateKey) Sign(
	rand io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
) ([]byte, error) {

	return r.key.Sign(rand, digest, opts)

}

// Decrypt implements the `crypto.Decrypter` _interface_. If opts is `nil` or of type
// `*PKCS1v15DecryptOptions` then _PKCS #1 v1.5_ decryption is performed. Otherwise
// opts must have type `*OAEPOptions` and _OAEP_ decryption is done.
func (r *RSAPrivateKey) Decrypt(
	rand io.Reader,
	msg []byte,
	opts crypto.DecrypterOpts,
) (plaintext []byte, err error) {

	return r.key.Decrypt(rand, msg, opts)

}

// GetPublic returns the public portion of the key
func (r *RSAPrivateKey) GetPublic() ifcrypto.PublicKey {
	return r.public
}

// PEMWrite will write the key onto _w_.
//
// If private key, and _public_ is `true`, it will in addition write the public portion as well.
func (r *RSAPrivateKey) PEMWrite(w io.Writer, public bool) error {

	return cryptoutils.RSAPrivateKeyToPEM(w, r.key, public)

}

// GetKey gets the underlying key, if any.
//
// Some keys are remote and not possible to fetch. In such situations the function returns a remote id,
// most often the same as GetID() returns.
func (r *RSAPrivateKey) GetKey() interface{} {
	return r.key
}

// IsSymmetric returns `true` if this is a `KeyTypeSymmetric`
//
// This is a convenience function instead of `GetKeyType`.
func (r *RSAPrivateKey) IsSymmetric() bool {
	return false
}

// IsPrivate returns `true` if this is a `KeyType` other than `KeyTypeSymmetric` and is a private key.
//
// If `KeyTypeSymmetric` it will return `true` since all symmetric keys are considered as private.
func (r *RSAPrivateKey) IsPrivate() bool {
	return true
}

// IsRemoteKey returns `true` if the key is not present in current process memory.
//
// Typically hardware units or remote services will not reveal their private key. In such case, this
// method returns `true`. If present in memory such as a `*rsa.PrivateKey` it returns `false`.
func (r *RSAPrivateKey) IsRemoteKey() bool {
	return false
}

// RSAPublicKey implements the `ifcrypto.PublicKey` interface for `*rsa.PublicKey`
type RSAPublicKey struct {
	KeyBase
	key *rsa.PublicKey
}

// NewRSAPublicKeyFromKey creates a instance based on a existing public key.
func NewRSAPublicKeyFromKey(
	id string,
	key *rsa.PublicKey,
	usage ...ifcrypto.KeyUsage,
) *RSAPublicKey {

	return &RSAPublicKey{
		KeyBase: KeyBase{
			id:      id,
			keyType: ifcrypto.KeyTypeRsa,
			keySize: key.Size(),
			usage:   usage,
		},
		key: key,
	}

}

// NewRSAPublicKeyFromPEM initializes a new `*rsa.PublicKey` from the underlying _PEM_ block.
func NewRSAPublicKeyFromPEM(
	block pem.Block,
	id string,
	usage ...ifcrypto.KeyUsage,
) (*RSAPublicKey, error) {

	if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {

		key, err := x509.ParsePKIXPublicKey(block.Bytes)

		if err != nil {
			return nil, err
		}

		if rsakey, ok := key.(*rsa.PublicKey); ok {

			return NewRSAPublicKeyFromKey(id, rsakey, usage...), nil

		}

		return nil, fmt.Errorf("not a *rsa.PublicKey: %T", key)

	}

	return nil, fmt.Errorf("unsupported PEM block: %s", block.Type)

}

// PEMWrite will write the key onto _w_.
//
// Since this is a public key, it will ignore the _public_ parameter.
func (r *RSAPublicKey) PEMWrite(w io.Writer, public bool) error {

	return cryptoutils.RSAPublicKeyToPEM(w, r.key)

}

// GetKey gets the underlying key, if any.
//
// Some keys are remote and not possible to fetch. In such situations the function returns a remote id,
// most often the same as GetID() returns.
func (r *RSAPublicKey) GetKey() interface{} {
	return r.key
}

// IsSymmetric returns `true` if this is a `KeyTypeSymmetric`
//
// This is a convenience function instead of `GetKeyType`.
func (r *RSAPublicKey) IsSymmetric() bool {
	return false
}

// IsPrivate returns `true` if this is a `KeyType` other than `KeyTypeSymmetric` and is a private key.
//
// If `KeyTypeSymmetric` it will return `true` since all symmetric keys are considered as private.
func (r *RSAPublicKey) IsPrivate() bool {
	return true
}

// IsRemoteKey returns `true` if the key is not present in current process memory.
//
// Typically hardware units or remote services will not reveal their private key. In such case, this
// method returns `true`. If present in memory such as a `*rsa.PrivateKey` it returns `false`.
func (r *RSAPublicKey) IsRemoteKey() bool {
	return false
}
