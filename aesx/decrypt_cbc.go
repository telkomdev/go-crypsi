package aesx

import (
	"errors"
	"io"
)

// DecryptWithAES128CBC will decrypt data with 128 bit key and with CBC mode
func DecryptWithAES128CBC(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}

// DecryptWithAES192CBC will decrypt data with 192 bit key and with CBC mode
func DecryptWithAES192CBC(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}

// DecryptWithAES256CBC will decrypt data with 256 bit key and with CBC mode
func DecryptWithAES256CBC(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return decrypt(AesCBC, key, encryptedData)
}

// io

// DecryptWithAES128CBCIO will decrypt data with 128 bit key and with CBC mode from io.Writer and io.Reader
func DecryptWithAES128CBCIO(key []byte, encryptedData io.Reader, plainData io.Writer) error {
	if len(key) != int(Aes128KeySize) {
		return errors.New("aes 128 must have 16 bytes key size")
	}

	return decryptIO(AesCBC, key, encryptedData, plainData)
}

// DecryptWithAES192CBCIO will decrypt data with 192 bit key and with CBC mode from io.Writer and io.Reader
func DecryptWithAES192CBCIO(key []byte, encryptedData io.Reader, plainData io.Writer) error {
	if len(key) != int(Aes192KeySize) {
		return errors.New("aes 192 must have 24 bytes key size")
	}

	return decryptIO(AesCBC, key, encryptedData, plainData)
}

// DecryptWithAES256CBCIO will decrypt data with 256 bit key and with CBC mode from io.Writer and io.Reader
func DecryptWithAES256CBCIO(key []byte, encryptedData io.Reader, plainData io.Writer) error {
	if len(key) != int(Aes256KeySize) {
		return errors.New("aes 256 must have 32 bytes key size")
	}

	return decryptIO(AesCBC, key, encryptedData, plainData)
}
