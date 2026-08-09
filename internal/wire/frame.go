// Package wire implements the bounded length-prefixed JSON headers used at the
// start of each p2pstore request and response direction.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxHeaderSize bounds an encoded JSON header before allocation or decoding.
const MaxHeaderSize = 64 * 1024

// ErrHeaderTooLarge reports an outbound or inbound header over MaxHeaderSize.
var ErrHeaderTooLarge = errors.New("p2pstore wire header exceeds 64 KiB")

// WriteHeader encodes value as JSON preceded by its four-byte, big-endian
// length. It does not write any operation body.
func WriteHeader(w io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > MaxHeaderSize {
		return ErrHeaderTooLarge
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err = w.Write(length[:]); err != nil {
		return err
	}
	_, err = w.Write(encoded)
	return err
}

// ReadHeader reads one bounded, length-prefixed JSON value into destination.
// Oversized lengths are rejected before allocating the JSON buffer.
func ReadHeader(r io.Reader, destination any) error {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 {
		return errors.New("p2pstore wire header is empty")
	}
	if size > MaxHeaderSize {
		return fmt.Errorf("%w: %d bytes", ErrHeaderTooLarge, size)
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(r, encoded); err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, destination); err != nil {
		return fmt.Errorf("decode p2pstore wire header: %w", err)
	}
	return nil
}
