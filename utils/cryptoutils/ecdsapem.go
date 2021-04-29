package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

// WriteECDSAKeys writes the private key onto _w_ using the PEM format.
//
// If _public_ is set to `true`, it will include public as well.
func ECDSAPrivateKeyToPEM(w io.Writer, key *ecdsa.PrivateKey, public bool) error {

	if key == nil {
		return fmt.Errorf("must specify private key to write")
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(key)

	if err != nil {
		return err
	}

	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	if err := pem.Encode(w, privateKeyBlock); err != nil {
		return err
	}

	if public {

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)

		if err != nil {
			return err
		}

		publicKeyBlock := &pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: publicKeyBytes,
		}

		if err = pem.Encode(w, publicKeyBlock); err != nil {
			return err
		}

	}

	return nil

}

// WriteECDSAPublicKey writes the public key onto the _w_ `io.Writer`.
func ECDSAPublicKeyToPEM(w io.Writer, key *ecdsa.PublicKey) error {

	if key == nil {
		return fmt.Errorf("must specify public key to write")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)

	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	if err = pem.Encode(w, publicKeyBlock); err != nil {
		return err
	}

	return nil
}

func PEMToECDSAPrivateKey(data []byte) (key *ecdsa.PrivateKey, err error) {

	var keys []interface{}
	keys, err = PEMToKey("", data,
		func(fqPath string, block *pem.Block) (key interface{}, stop bool, err error) {

			var k interface{}
			if strings.HasPrefix(block.Type, "EC") {

				if k, err = x509.ParseECPrivateKey(block.Bytes); err == nil {
					key = k
					stop = true
				}

			} else {

				if k, err = x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
					key = k
					stop = true
				}

			}

			return

		}, "PRIVATE KEY", "EC PRIVATE KEY")

	return keys[0].(*ecdsa.PrivateKey), err
}

func PEMToECDSAPublicKey(data []byte) (key *ecdsa.PublicKey, err error) {

	var keys []interface{}
	keys, err = PEMToKey("", data,
		func(fqPath string, block *pem.Block) (key interface{}, stop bool, err error) {

			var k interface{}
			if k, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				key = k
				stop = true
			}

			return

		}, "PUBLIC KEY", "EC PUBLIC KEY")

	return keys[0].(*ecdsa.PublicKey), err
}
