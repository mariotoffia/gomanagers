package ifkms

import (
	"github.com/mariotoffia/gomanagers/interfaces/ifcrypto"
	"github.com/mariotoffia/gomanagers/model/coremodel"
)

// Signer is a entity that may sign or verify a signature.
type Signer interface {
	// Sign will sign the _msg_ using the provided _key_.
	Sign(
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	)

	// Verify will verify the _msg_ using the provided _key_
	Verify(
		msg []byte,
		key ifcrypto.Key,
		signAlgorithm ifcrypto.SignAlgorithm,
		tags ...coremodel.Meta,
	)
}
