package digest

import (
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// Sha512 returns the Sha512 checksum of the data
func Sha512(datas ...[]byte) ([]byte, error) {
	return digest(sha512.New(), datas...)
}

// Sha512Hex returns the Sha512 checksum of the data with HEX format
func Sha512Hex(datas ...[]byte) (string, error) {
	b, err := digest(sha512.New(), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha512IO returns the Sha512 checksum of the io.Reader
func Sha512IO(r io.Reader) ([]byte, error) {
	return digestIO(sha512.New(), r)
}

// Sha512IOHex returns the Sha512 checksum of the io.Reader with HEX format
func Sha512IOHex(r io.Reader) (string, error) {
	b, err := digestIO(sha512.New(), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
