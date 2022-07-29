package hmacx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
)

// Sha256 returns the Sha256 HMAC of the data
func Sha256(key []byte, datas ...[]byte) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return mac(hmac.New(sha256.New, key), datas...)
}

// Sha256Hex returns the Sha256 HMAC of the data with HEX format
func Sha256Hex(key []byte, datas ...[]byte) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := mac(hmac.New(sha256.New, key), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha256IO returns the Sha256 HMAC of the io.Reader
func Sha256IO(key []byte, r io.Reader) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return macIO(hmac.New(sha256.New, key), r)
}

// Sha256IOHex returns the Sha256 HMAC of the io.Reader with HEX format
func Sha256IOHex(key []byte, r io.Reader) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := macIO(hmac.New(sha256.New, key), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
