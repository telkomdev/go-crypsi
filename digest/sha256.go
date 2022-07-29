package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Sha256 returns the Sha256 checksum of the data
func Sha256(datas ...[]byte) ([]byte, error) {
	return digest(sha256.New(), datas...)
}

// Sha256Hex returns the Sha256 checksum of the data with HEX format
func Sha256Hex(datas ...[]byte) (string, error) {
	b, err := digest(sha256.New(), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha256IO returns the Sha256 checksum of the io.Reader
func Sha256IO(r io.Reader) ([]byte, error) {
	return digestIO(sha256.New(), r)
}

// Sha256IOHex returns the Sha256 checksum of the io.Reader with HEX format
func Sha256IOHex(r io.Reader) (string, error) {
	b, err := digestIO(sha256.New(), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
