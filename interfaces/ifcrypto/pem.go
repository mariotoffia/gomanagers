package ifcrypto

import "io"

// PEMWriter allows for writing the key
type PEMWriter interface {

	// PEMWrite will write the key onto _w_.
	//
	// If private key, and _public_ is `true`, it
	// will in addition write the public portion as well.
	PEMWrite(w io.Writer, public bool) error
}
