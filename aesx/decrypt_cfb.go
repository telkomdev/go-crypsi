package aesx

import (
	"errors"
)

// DecryptWithAES128CFB will decrypt data with 128 bit key and with CFB mode
func DecryptWithAES128CFB(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return decrypt(AesCFB, key, encryptedData)
}

// DecryptWithAES192CFB will decrypt data with 192 bit key and with CFB mode
func DecryptWithAES192CFB(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return decrypt(AesCFB, key, encryptedData)
}

// DecryptWithAES256CFB will decrypt data with 256 bit key and with CFB mode
func DecryptWithAES256CFB(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return decrypt(AesCFB, key, encryptedData)
}
