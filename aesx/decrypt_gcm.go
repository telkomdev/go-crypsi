package aesx

import (
	"errors"
)

// DecryptWithAES128GCM will decrypt data with 128 bit key and with GCM mode
func DecryptWithAES128GCM(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes128KeySize) {
		return nil, errors.New("aes 128 must have 16 bytes key size")
	}

	return decrypt(AesGCM, key, encryptedData)
}

// DecryptWithAES192GCM will decrypt data with 192 bit key and with GCM mode
func DecryptWithAES192GCM(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes192KeySize) {
		return nil, errors.New("aes 192 must have 24 bytes key size")
	}

	return decrypt(AesGCM, key, encryptedData)
}

// DecryptWithAES256GCM will decrypt data with 256 bit key and with GCM mode
func DecryptWithAES256GCM(key []byte, encryptedData *AesData) ([]byte, error) {
	if len(key) != int(Aes256KeySize) {
		return nil, errors.New("aes 256 must have 32 bytes key size")
	}

	return decrypt(AesGCM, key, encryptedData)
}
