package cryptoutils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
)

// WriteRSAKeys writes the private key onto _w_ using the PEM format.
//
// If _public_ is set to `true`, it will include public as well.
func RSAPrivateKeyToPEM(w io.Writer, key *rsa.PrivateKey, public bool) error {

	if key == nil {
		return fmt.Errorf("must specify private key to write")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(key)

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
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
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		}

		if err = pem.Encode(w, publicKeyBlock); err != nil {
			return err
		}

	}

	return nil

}

// WriteRSAPublicKey writes the public key onto the _w_ `io.Writer`.
func RSAPublicKeyToPEM(w io.Writer, key *rsa.PublicKey) error {

	if key == nil {
		return fmt.Errorf("must specify public key to write")
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)

	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	if err = pem.Encode(w, publicKeyBlock); err != nil {
		return err
	}

	return nil
}

func PEMToRSAPrivateKey(data []byte) (key *rsa.PrivateKey, err error) {

	var keys []interface{}
	keys, err = PEMToKey("", data,
		func(fqPath string, block *pem.Block) (key interface{}, stop bool, err error) {

			var k interface{}
			if strings.HasPrefix(block.Type, "RSA") {

				if k, err = x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
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

		}, "PRIVATE KEY", "RSA PRIVATE KEY")

	return keys[0].(*rsa.PrivateKey), err
}

func PEMToRSAPublicKey(data []byte) (key *rsa.PublicKey, err error) {

	var keys []interface{}
	keys, err = PEMToKey("", data,
		func(fqPath string, block *pem.Block) (key interface{}, stop bool, err error) {

			var k interface{}
			if k, err = x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				key = k
				stop = true
			}

			return

		}, "PUBLIC KEY", "RSA PUBLIC KEY")

	return keys[0].(*rsa.PublicKey), err
}
