package rsax

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

func decryptWithOAEP(privateKey *rsa.PrivateKey,
	h hash.Hash, encryptedDataBytes []byte) ([]byte, error) {
	decryptedDataBytes, err := rsa.DecryptOAEP(h, rand.Reader, privateKey, encryptedDataBytes, nil)
	if err != nil {
		return nil, err
	}

	return decryptedDataBytes, nil
}

// DecryptWithOAEPMd5 will decrypt data with data with RSA OAEP and MD5
func DecryptWithOAEPMd5(privateKey *rsa.PrivateKey, encryptedDataBytes []byte) ([]byte, error) {
	h := md5.New()
	return decryptWithOAEP(privateKey, h, encryptedDataBytes)
}

// DecryptWithOAEPSha1 will decrypt data with data with RSA OAEP and Sha1
func DecryptWithOAEPSha1(privateKey *rsa.PrivateKey, encryptedDataBytes []byte) ([]byte, error) {
	h := sha1.New()
	return decryptWithOAEP(privateKey, h, encryptedDataBytes)
}

// DecryptWithOAEPSha256 will decrypt data with data with RSA OAEP and Sha256
func DecryptWithOAEPSha256(privateKey *rsa.PrivateKey, encryptedDataBytes []byte) ([]byte, error) {
	h := sha256.New()
	return decryptWithOAEP(privateKey, h, encryptedDataBytes)
}

// DecryptWithOAEPSha384 will decrypt data with data with RSA OAEP and Sha384
func DecryptWithOAEPSha384(privateKey *rsa.PrivateKey, encryptedDataBytes []byte) ([]byte, error) {
	h := sha512.New384()
	return decryptWithOAEP(privateKey, h, encryptedDataBytes)
}

// DecryptWithOAEPSha512 will decrypt data with data with RSA OAEP and Sha512
func DecryptWithOAEPSha512(privateKey *rsa.PrivateKey, encryptedDataBytes []byte) ([]byte, error) {
	h := sha512.New()
	return decryptWithOAEP(privateKey, h, encryptedDataBytes)
}
