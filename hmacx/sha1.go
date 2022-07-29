package hmacx

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io"
)

// Sha1 returns the Sha1 HMAC of the data
func Sha1(key []byte, datas ...[]byte) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return mac(hmac.New(sha1.New, key), datas...)
}

// Sha1Hex returns the Sha1 HMAC of the data with HEX format
func Sha1Hex(key []byte, datas ...[]byte) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := mac(hmac.New(sha1.New, key), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Sha1IO returns the Sha1 HMAC of the io.Reader
func Sha1IO(key []byte, r io.Reader) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return macIO(hmac.New(sha1.New, key), r)
}

// Sha1IOHex returns the Sha1 HMAC of the io.Reader with HEX format
func Sha1IOHex(key []byte, r io.Reader) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := macIO(hmac.New(sha1.New, key), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
