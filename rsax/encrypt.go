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

// https://pkg.go.dev/crypto/rsa@go1.19.1#EncryptOAEP
func encryptWithOAEP(publicKey *rsa.PublicKey,
	h hash.Hash, plainDataBytes []byte) ([]byte, error) {
	encryptedDataBytes, err := rsa.EncryptOAEP(h, rand.Reader, publicKey, plainDataBytes, nil)
	if err != nil {
		return nil, err
	}

	return encryptedDataBytes, nil
}

// EncryptWithOAEPMd5 will encrypt data with data with RSA OAEP and MD5
func EncryptWithOAEPMd5(publicKey *rsa.PublicKey, plainDataBytes []byte) ([]byte, error) {
	h := md5.New()
	return encryptWithOAEP(publicKey, h, plainDataBytes)
}

// EncryptWithOAEPSha1 will encrypt data with data with RSA OAEP and Sha1
func EncryptWithOAEPSha1(publicKey *rsa.PublicKey, plainDataBytes []byte) ([]byte, error) {
	h := sha1.New()
	return encryptWithOAEP(publicKey, h, plainDataBytes)
}

// EncryptWithOAEPSha256 will encrypt data with data with RSA OAEP and Sha256
func EncryptWithOAEPSha256(publicKey *rsa.PublicKey, plainDataBytes []byte) ([]byte, error) {
	h := sha256.New()
	return encryptWithOAEP(publicKey, h, plainDataBytes)
}

// EncryptWithOAEPSha384 will encrypt data with data with RSA OAEP and Sha384
func EncryptWithOAEPSha384(publicKey *rsa.PublicKey, plainDataBytes []byte) ([]byte, error) {
	h := sha512.New384()
	return encryptWithOAEP(publicKey, h, plainDataBytes)
}

// EncryptWithOAEPSha512 will encrypt data with data with RSA OAEP and Sha512
func EncryptWithOAEPSha512(publicKey *rsa.PublicKey, plainDataBytes []byte) ([]byte, error) {
	h := sha512.New()
	return encryptWithOAEP(publicKey, h, plainDataBytes)
}
