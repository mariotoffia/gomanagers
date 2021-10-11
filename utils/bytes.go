package utils

import (
	"fmt"
	"io"
)

// ByteWriter will write the data as blocks of _chunkSize_.
//
// If it fails to write a whole _chunkSize_ it will return an error. If
// the data is "misaligned" it will write the leftover in a single write.
func ByteWriter(w io.Writer, data []byte, chunkSize int) error {

	chunks := len(data) / chunkSize

	for i := 0; i < chunks; i++ {

		start := chunkSize * i
		end := chunkSize*i + chunkSize

		written, err := w.Write(data[start:end])

		if err != nil {
			return err
		}

		if written != chunkSize {

			return fmt.Errorf(
				"written: %d != chunk size: %d", written, chunkSize,
			)

		}

	}

	left := len(data) - chunkSize*chunks

	if left > 0 {

		written, err := w.Write(data[chunkSize*chunks:])
		if err != nil {
			return err
		}

		if written != left {

			return fmt.Errorf(
				"written: %d != left: %d", written, left,
			)

		}

	}

	return nil
}
