package ifcrypto

import "github.com/mariotoffia/goservice/interfaces/ifctx"

// Cipherable is a encrypt / decrypt capable implementation.
//
// NOTE: Some keys do implement `crypto.Decrypter`, thus is
// able to decrypt via the key directly.
type Cipherable interface {
	// Encrypt will encrypt the _plaintext_ using the key.
	Encrypt(
		c ifctx.ServiceContext,
		plaintext []byte,
		key Key,
		cipher Chipher,
	) (encrypted []byte, err error)

	// Decrypt will decrypt the _encrypted_ using the key.
	Decrypt(
		c ifctx.ServiceContext,
		encrypted []byte,
		key Key,
		cipher Chipher,
	) (plaintext []byte, err error)
}
