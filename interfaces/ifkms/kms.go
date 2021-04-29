package ifkms

import (
	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/model/coremodel"
)

// Signer is a entity that may sign a signature.
type Signer interface {
	// Sign will sign the _msg_ using the provided _key_.
	Sign(
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	)
}

// Verifier is implemented by those who may verify a signature.
type Verifier interface {
	// Verify will verify the _msg_ using the provided _key_
	Verify(
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	)
}
