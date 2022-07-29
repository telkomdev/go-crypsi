package digestx

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
)

// Sha1 returns the Sha1 checksum of the data
func Sha1(datas ...[]byte) ([]byte, error) {
	return digest(sha1.New(), datas...)
}

// Sha1Hex returns the Sha1 checksum of the data with HEX format
func Sha1Hex(datas ...[]byte) (string, error) {
	b, err := digest(sha1.New(), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha1IO returns the Sha1 checksum of the io.Reader
func Sha1IO(r io.Reader) ([]byte, error) {
	return digestIO(sha1.New(), r)
}

// Sha1IOHex returns the Sha1 checksum of the io.Reader with HEX format
func Sha1IOHex(r io.Reader) (string, error) {
	b, err := digestIO(sha1.New(), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
