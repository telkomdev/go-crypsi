package aesx

import (
	"errors"
)

// DecryptWithAES128CBC will decrypt data with 128 bit key and with CBC mode
func DecryptWithAES128CBC(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}

// DecryptWithAES192CBC will decrypt data with 192 bit key and with CBC mode
func DecryptWithAES192CBC(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}

// DecryptWithAES256CBC will decrypt data with 256 bit key and with CBC mode
func DecryptWithAES256CBC(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}
