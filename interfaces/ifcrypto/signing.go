package ifcrypto

import (
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
		key Key,
		signAlgorithm SignAlgorithm,
		tags ...coremodel.Meta,
	) error
}

// Verifier is implemented by those who may verify a signature.
type Verifier interface {
	// Verify will verify the _msg_ using the provided _key_
	Verify(
		c ifctx.ServiceContext,
		msg []byte,
		key Key,
		signAlgorithm SignAlgorithm,
		tags ...coremodel.Meta,
	) error
}
