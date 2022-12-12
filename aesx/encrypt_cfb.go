package aesx

import (
	"errors"
	"io"
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

// io

// EncryptWithAES128CFBIO will encrypt data with 128 bit key and with CFB mode from io.Writer and io.Reader
func EncryptWithAES128CFBIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes128KeySize) {
		return errors.New("aes 128 must have 16 bytes key size")
	}

	return encryptIO(AesCFB, key, plainData, encryptedData)
}

// EncryptWithAES192CFBIO will encrypt data with 192 bit key and with CFB mode from io.Writer and io.Reader
func EncryptWithAES192CFBIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes192KeySize) {
		return errors.New("aes 192 must have 24 bytes key size")
	}

	return encryptIO(AesCFB, key, plainData, encryptedData)
}

// EncryptWithAES256CFBIO will encrypt data with 256 bit key and with CFB mode from io.Writer and io.Reader
func EncryptWithAES256CFBIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes256KeySize) {
		return errors.New("aes 256 must have 32 bytes key size")
	}

	return encryptIO(AesCFB, key, plainData, encryptedData)
}
