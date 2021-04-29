package cryptoutils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// PEMToKeyFactory creates keys from a pem input.
//
// If the function sets `true` in _stop_ or returns an error. The _PEM_ stops immediately.
// If it returns an error, the `PEMToKey` function will return the same error along with no keys.
//
// If the function do not return a key, it will be silently ignored, hence it is possible to
// do selective decoding of keys.
//
// The _fqPath_ may be empty string if the factory was invoked on data without any path information.
type PEMToKeyFactory func(fqPath string, block *pem.Block) (key interface{}, stop bool, err error)

// PEMKeysFromFS loads a set of keys stored in _PEM_ files on the _fsys_.
//
// The _glob_ is a `glob.Glob` expression to capture one or more files (recursively), for example
// _"**.pem"_ will capture all files ending with _.pem_ recursively down folders. If empty string
// the default is _"**.pem"_
//
// The dir string is in which subdirectory to start, if empty string, it will start at root level.
//
// All other parameters are the same as the `PEMToKey` function.
func PEMKeysFromFS(fsys fs.FS,
	dir string,
	glob string,
	parser PEMToKeyFactory,
	keyTypes ...string,
) (keys []interface{}, err error) {

	keys = []interface{}{}

	if glob == "" {
		glob = "**.pem"
	}

	/* TODO: replace me with standard walker
	err = utils.FSWalker(fsys, "", glob, true,
		func(f fs.FS, fqPath string, data []byte) error {

			k, err := PEMToKey(fqPath, data, parser, keyTypes...)

			if err != nil {

				return cberror.NewCbErrorf(
					1, err,
					"failed to parse keys from pem file: %s",
					fqPath,
				)

			}

			if len(k) > 0 {

				keys = append(keys, k...)

			}

			return nil

		})

	if err != nil {

		return

	}*/

	return keys, nil

}

// PEMToKey decods the _data_ and uses the _parser_ function to parse out the actual key(s).
//
// The parameter _fqPath_ is optional to denote where the _pemData_ was taken from.
func PEMToKey(
	fqPath string,
	pemData []byte,
	parser PEMToKeyFactory,
	keyTypes ...string,
) (keys []interface{}, err error) {

	keys = []interface{}{}

	rest := pemData
	for len(rest) > 0 {

		var block *pem.Block
		block, rest = pem.Decode(rest)

		if block == nil {

			if len(keys) > 0 {
				return
			}

			return nil, fmt.Errorf("got nil PEM block")

		}

		if len(keyTypes) > 0 {

			/*TODO:
			if !utils.Contains(keyTypes, block.Type) {
				continue
			}*/

		}

		key, stop, err := parser(fqPath, block)

		if err != nil {
			return nil, err
		}

		if key != nil {

			keys = append(keys, key)

		}

		if stop {
			break
		}

	}

	return
}

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
