package aesx

import (
	"errors"
	"io"
)

// EncryptWithAES128GCM will encrypt data with 128 bit key and with GCM mode
func EncryptWithAES128GCM(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return encrypt(AesGCM, key, plainData)
}

// EncryptWithAES192GCM will encrypt data with 192 bit key and with GCM mode
func EncryptWithAES192GCM(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return encrypt(AesGCM, key, plainData)
}

// EncryptWithAES256GCM will encrypt data with 256 bit key and with GCM mode
func EncryptWithAES256GCM(key []byte, plainData []byte) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return encrypt(AesGCM, key, plainData)
}

// io

// EncryptWithAES128GCMIO will encrypt data with 128 bit key and with GCM mode from io.Writer and io.Reader
func EncryptWithAES128GCMIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes128KeySize) {
		return errors.New("aes 128 must have 16 bytes key size")
	}

	return encryptIO(AesGCM, key, plainData, encryptedData)
}

// EncryptWithAES192GCMIO will encrypt data with 192 bit key and with GCM mode from io.Writer and io.Reader
func EncryptWithAES192GCMIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes192KeySize) {
		return errors.New("aes 192 must have 24 bytes key size")
	}

	return encryptIO(AesGCM, key, plainData, encryptedData)
}

// EncryptWithAES256GCMIO will encrypt data with 256 bit key and with GCM mode from io.Writer and io.Reader
func EncryptWithAES256GCMIO(key []byte, plainData io.Reader, encryptedData io.Writer) error {
	if len(key) != int(Aes256KeySize) {
		return errors.New("aes 256 must have 32 bytes key size")
	}

	return encryptIO(AesGCM, key, plainData, encryptedData)
}
