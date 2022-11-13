package aesx

import (
	"errors"
)

// EncryptWithAES128CBC will encrypt data with 128 bit key and with CBC mode
func EncryptWithAES128CBC(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return encrypt(AesCBC, key, plainData)
}

// EncryptWithAES192CBC will encrypt data with 192 bit key and with CBC mode
func EncryptWithAES192CBC(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return encrypt(AesCBC, key, plainData)
}

// EncryptWithAES256CBC will encrypt data with 256 bit key and with CBC mode
func EncryptWithAES256CBC(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return encrypt(AesCBC, key, plainData)
}
