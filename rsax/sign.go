package rsax

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
)

// https://pkg.go.dev/crypto/rsa@go1.19.1#SignPSS
func signWithPSS(privateKey *rsa.PrivateKey,
	d hash.Hash, h crypto.Hash, data []byte) ([]byte, error) {

	_, err := d.Write(data)
	if err != nil {
		return nil, err
	}

	msgHashSum := d.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, h, msgHashSum, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func signWithPSSIO(privateKey *rsa.PrivateKey,
	d hash.Hash, h crypto.Hash, data io.Reader) ([]byte, error) {

	_, err := io.Copy(d, data)
	if err != nil {
		return nil, err
	}

	msgHashSum := d.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, h, msgHashSum, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

// SignWithPSSMd5 will sign data RSA PSS and MD5
func SignWithPSSMd5(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := md5.New()
	return signWithPSS(privateKey, h, crypto.MD5, data)
}

// SignWithPSSSha1 will sign data RSA PSS and Sha1
func SignWithPSSSha1(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha1.New()
	return signWithPSS(privateKey, h, crypto.SHA1, data)
}

// SignWithPSSSha256 will sign data RSA PSS and Sha256
func SignWithPSSSha256(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.New()
	return signWithPSS(privateKey, h, crypto.SHA256, data)
}

// SignWithPSSSha384 will sign data RSA PSS and Sha384
func SignWithPSSSha384(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha512.New384()
	return signWithPSS(privateKey, h, crypto.SHA384, data)
}

// SignWithPSSSha512 will sign data RSA PSS and Sha512
func SignWithPSSSha512(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha512.New()
	return signWithPSS(privateKey, h, crypto.SHA512, data)
}

// from io.Reader

// SignWithPSSMd5IO will sign data RSA PSS and MD5 from io.Reader
func SignWithPSSMd5IO(privateKey *rsa.PrivateKey, data io.Reader) ([]byte, error) {
	h := md5.New()
	return signWithPSSIO(privateKey, h, crypto.MD5, data)
}

// SignWithPSSSha1IO will sign data RSA PSS and Sha1 from io.Reader
func SignWithPSSSha1IO(privateKey *rsa.PrivateKey, data io.Reader) ([]byte, error) {
	h := sha1.New()
	return signWithPSSIO(privateKey, h, crypto.SHA1, data)
}

// SignWithPSSSha256IO will sign data RSA PSS and Sha256 from io.Reader
func SignWithPSSSha256IO(privateKey *rsa.PrivateKey, data io.Reader) ([]byte, error) {
	h := sha256.New()
	return signWithPSSIO(privateKey, h, crypto.SHA256, data)
}

// SignWithPSSSha384IO will sign data RSA PSS and Sha384 from io.Reader
func SignWithPSSSha384IO(privateKey *rsa.PrivateKey, data io.Reader) ([]byte, error) {
	h := sha512.New384()
	return signWithPSSIO(privateKey, h, crypto.SHA384, data)
}

// SignWithPSSSha512IO will sign data RSA PSS and Sha512 from io.Reader
func SignWithPSSSha512IO(privateKey *rsa.PrivateKey, data io.Reader) ([]byte, error) {
	h := sha512.New()
	return signWithPSSIO(privateKey, h, crypto.SHA512, data)
}
