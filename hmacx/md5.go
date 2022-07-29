package hmacx

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"io"
)

// Md5 returns the MD5 HMAC of the data
func Md5(key []byte, datas ...[]byte) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return mac(hmac.New(md5.New, key), datas...)
}

// Md5Hex returns the MD5 HMAC of the data with HEX format
func Md5Hex(key []byte, datas ...[]byte) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := mac(hmac.New(md5.New, key), datas...)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

// Md5IO returns the MD5 HMAC of the io.Reader
func Md5IO(key []byte, r io.Reader) ([]byte, error) {
	if err := checkKeyLen(key); err != nil {
		return nil, err
	}

	return macIO(hmac.New(md5.New, key), r)
}

// Md5IOHex returns the MD5 HMAC of the io.Reader with HEX format
func Md5IOHex(key []byte, r io.Reader) (string, error) {
	if err := checkKeyLen(key); err != nil {
		return "", err
	}

	b, err := macIO(hmac.New(md5.New, key), r)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
