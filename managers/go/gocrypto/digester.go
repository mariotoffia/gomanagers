package gocrypto

import (
	"fmt"

	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/utils"
)

type GoDigester int

func NewDigester() GoDigester {
	return 0
}

// Digest implements the `ifcrypto.Digester` interface.
func (d GoDigester) Digest(key, msg []byte, h ...ifcrypto.HashAlgorithm) ([]byte, error) {

	l := len(h)

	if l == 0 || l > 2 {
		return nil, fmt.Errorf("number of hash algorithms must be either one or two")
	}

	hsh := h[0].GetHasher()

	if l == 2 {
		hsh = h[1].GetHasherWithKey(key, hsh)
	}

	if hsh == nil {
		return nil, fmt.Errorf("nil hasher")
	}

	if err := utils.ByteWriter(hsh, msg, hsh.BlockSize()); err != nil {

		return nil, err

	}

	return hsh.Sum(nil), nil
}
