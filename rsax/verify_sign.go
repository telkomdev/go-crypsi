package rsax

import (
	"crypto"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
)

// https://pkg.go.dev/crypto/rsa@go1.19.1#VerifyPSS
func verifySignatureWithPSS(publicKey *rsa.PublicKey,
	d hash.Hash, h crypto.Hash, signature, data []byte) error {

	_, err := d.Write(data)
	if err != nil {
		return err
	}

	msgHashSum := d.Sum(nil)

	return rsa.VerifyPSS(publicKey, h,
		msgHashSum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

func verifySignatureWithPSSIO(publicKey *rsa.PublicKey,
	d hash.Hash, h crypto.Hash, signature []byte, data io.Reader) error {

	_, err := io.Copy(d, data)
	if err != nil {
		return err
	}

	msgHashSum := d.Sum(nil)

	return rsa.VerifyPSS(publicKey, h,
		msgHashSum, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
}

// VerifySignatureWithPSSMd5 will verify signature data with RSA PSS and MD5
func VerifySignatureWithPSSMd5(publicKey *rsa.PublicKey, signature, data []byte) error {
	h := md5.New()
	return verifySignatureWithPSS(publicKey, h, crypto.MD5, signature, data)
}

// VerifySignatureWithPSSSha1 will verify signature data with RSA PSS and Sha1
func VerifySignatureWithPSSSha1(publicKey *rsa.PublicKey, signature, data []byte) error {
	h := sha1.New()
	return verifySignatureWithPSS(publicKey, h, crypto.SHA1, signature, data)
}

// VerifySignatureWithPSSSha256 will verify signature data with RSA PSS and Sha256
func VerifySignatureWithPSSSha256(publicKey *rsa.PublicKey, signature, data []byte) error {
	h := sha256.New()
	return verifySignatureWithPSS(publicKey, h, crypto.SHA256, signature, data)
}

// VerifySignatureWithPSSSha384 will verify signature data with RSA PSS and Sha384
func VerifySignatureWithPSSSha384(publicKey *rsa.PublicKey, signature, data []byte) error {
	h := sha512.New384()
	return verifySignatureWithPSS(publicKey, h, crypto.SHA384, signature, data)
}

// VerifySignatureWithPSSSha512 will verify signature data with RSA PSS and Sha512
func VerifySignatureWithPSSSha512(publicKey *rsa.PublicKey, signature, data []byte) error {
	h := sha512.New()
	return verifySignatureWithPSS(publicKey, h, crypto.SHA512, signature, data)
}

// from io.Reader

// VerifySignatureWithPSSMd5IO will verify signature data with RSA PSS and MD5 from io.Reader
func VerifySignatureWithPSSMd5IO(publicKey *rsa.PublicKey, signature []byte, data io.Reader) error {
	h := md5.New()
	return verifySignatureWithPSSIO(publicKey, h, crypto.MD5, signature, data)
}

// VerifySignatureWithPSSSha1IO will verify signature data with RSA PSS and Sha1 from io.Reader
func VerifySignatureWithPSSSha1IO(publicKey *rsa.PublicKey, signature []byte, data io.Reader) error {
	h := sha1.New()
	return verifySignatureWithPSSIO(publicKey, h, crypto.SHA1, signature, data)
}

// VerifySignatureWithPSSSha256IO will verify signature data with RSA PSS and Sha256 from io.Reader
func VerifySignatureWithPSSSha256IO(publicKey *rsa.PublicKey, signature []byte, data io.Reader) error {
	h := sha256.New()
	return verifySignatureWithPSSIO(publicKey, h, crypto.SHA256, signature, data)
}

// VerifySignatureWithPSSSha384IO will verify signature data with RSA PSS and Sha384 from io.Reader
func VerifySignatureWithPSSSha384IO(publicKey *rsa.PublicKey, signature []byte, data io.Reader) error {
	h := sha512.New384()
	return verifySignatureWithPSSIO(publicKey, h, crypto.SHA384, signature, data)
}

// VerifySignatureWithPSSSha512IO will verify signature data with RSA PSS and Sha512 from io.Reader
func VerifySignatureWithPSSSha512IO(publicKey *rsa.PublicKey, signature []byte, data io.Reader) error {
	h := sha512.New()
	return verifySignatureWithPSSIO(publicKey, h, crypto.SHA512, signature, data)
}
