package hmacx

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"io"
)

// Sha512 returns the Sha512 HMAC of the data
func Sha512(key []byte, datas ...[]byte) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return mac(hmac.New(sha512.New, key), datas...)
}

// Sha512Hex returns the Sha512 HMAC of the data with HEX format
func Sha512Hex(key []byte, datas ...[]byte) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := mac(hmac.New(sha512.New, key), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha512IO returns the Sha512 HMAC of the io.Reader
func Sha512IO(key []byte, r io.Reader) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return macIO(hmac.New(sha512.New, key), r)
}

// Sha512IOHex returns the Sha512 HMAC of the io.Reader with HEX format
func Sha512IOHex(key []byte, r io.Reader) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := macIO(hmac.New(sha512.New, key), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
