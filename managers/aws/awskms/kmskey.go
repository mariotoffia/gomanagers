package awskms

import "github.com/mariotoffia/goservice/managers/go/gocrypto"

// KmsKey implements the `ifcrypto.Key` interface.
//
// The `GetID` represents the _KMS ARN_, alias or id of this key.
type KmsKey struct {
	// Derive from `gocrypto.KeyBase`
	gocrypto.KeyBase
}
