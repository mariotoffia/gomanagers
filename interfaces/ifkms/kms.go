package ifkms

import (
	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/interfaces/ifctx"
	"github.com/mariotoffia/goservice/model/coremodel"
)

// Signer is a entity that may sign a signature.
//
// NOTE: Some keys do implement `crypto.Signer` interface directly on the key.
type Signer interface {
	// Sign will sign the _msg_ using the provided _key_.
	Sign(
		c ifctx.ServiceContext,
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	) error
}

// Verifier is implemented by those who may verify a signature.
type Verifier interface {
	// Verify will verify the _msg_ using the provided _key_
	Verify(
		c ifctx.ServiceContext,
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	) error
}

// Cipherable is a encrypt / decrypt capable implementation.
//
// NOTE: Some keys do implement `crypto.Decrypter`, thus is
// able to decrypt via the key directly.
type Cipherable interface {
	// Encrypt will encrypt the _plaintext_ using the key.
	Encrypt(
		c ifctx.ServiceContext,
		plaintext []byte,
		key ifcrypto.Key,
		cipher ifcrypto.Chipher,
	) (encrypted []byte, err error)

	// Decrypt will decrypt the _encrypted_ using the key.
	Decrypt(
		c ifctx.ServiceContext,
		encrypted []byte,
		key ifcrypto.Key,
		cipher ifcrypto.Chipher,
	) (plaintext []byte, err error)
}
