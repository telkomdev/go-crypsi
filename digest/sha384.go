package digest

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// Sha384 returns the Sha384 checksum of the data
func Sha384(datas ...[]byte) ([]byte, error) {
	return digest(sha512.New384(), datas...)
}

// Sha384Hex returns the Sha384 checksum of the data with HEX format
func Sha384Hex(datas ...[]byte) (string, error) {
	b, err := digest(sha512.New384(), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha384IO returns the Sha384 checksum of the io.Reader
func Sha384IO(r io.Reader) ([]byte, error) {
	return digestIO(sha512.New384(), r)
}

// Sha384IOHex returns the Sha384 checksum of the io.Reader with HEX format
func Sha384IOHex(r io.Reader) (string, error) {
	b, err := digestIO(sha512.New384(), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
