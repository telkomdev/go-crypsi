package aesx

import (
	"errors"
)

// EncryptWithAES128CFB will encrypt data with 128 bit key and with CFB mode
func EncryptWithAES128CFB(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return encrypt(AesCFB, key, plainData)
}

// EncryptWithAES192CFB will encrypt data with 192 bit key and with CFB mode
func EncryptWithAES192CFB(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return encrypt(AesCFB, key, plainData)
}

// EncryptWithAES256CFB will encrypt data with 256 bit key and with CFB mode
func EncryptWithAES256CFB(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return encrypt(AesCFB, key, plainData)
}
