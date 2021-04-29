package cryptoutils

import (
	"encoding/pem"
	"fmt"
	"io/fs"

	"github.com/mariotoffia/goservice/utils"
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

			if _, ok := utils.Contains(keyTypes, block.Type); !ok {
				continue
			}

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
