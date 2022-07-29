package hmacx

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// Sha384 returns the Sha384 HMAC of the data
func Sha384(key []byte, datas ...[]byte) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return mac(hmac.New(sha512.New384, key), datas...)
}

// Sha384Hex returns the Sha384 HMAC of the data with HEX format
func Sha384Hex(key []byte, datas ...[]byte) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := mac(hmac.New(sha512.New384, key), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha384IO returns the Sha384 HMAC of the io.Reader
func Sha384IO(key []byte, r io.Reader) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return macIO(hmac.New(sha512.New384, key), r)
}

// Sha384IOHex returns the Sha384 HMAC of the io.Reader with HEX format
func Sha384IOHex(key []byte, r io.Reader) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := macIO(hmac.New(sha512.New384, key), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
