package rsax

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// KeySize RSA key size type
type KeySize int

const (
	// KeySize1Kb 1024
	KeySize1Kb KeySize = 1 << 10 // 1024

	// KeySize2Kb 2048
	KeySize2Kb KeySize = 1 << 11 // 2048

	// KeySize4Kb 4096
	KeySize4Kb KeySize = 1 << 12 // 4096
)

// RSAPairs represent RSA private and public key pairs
type RSAPairs struct {
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	PrivateKeyBytes []byte
	PublicKeyBytes  []byte
}

// GenerateKeyPairs will generate RSA key pairs
func GenerateKeyPairs(keySize KeySize) (*RSAPairs, error) {
	if keySize < KeySize1Kb {
		keySize = KeySize2Kb
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, int(keySize))
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey

	privateKeyBytes, err := privateKeyToBytes(privateKey)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := publicKeyToBytes(&publicKey)
	if err != nil {
		return nil, err
	}

	return &RSAPairs{
		PrivateKey:      privateKey,
		PublicKey:       &publicKey,
		PrivateKeyBytes: privateKeyBytes,
		PublicKeyBytes:  publicKeyBytes,
	}, nil

}

func publicKeyToBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return publicKeyBytes, nil
}

func privateKeyToBytes(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyPKCS8Form, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyPKCS8Form,
		},
	)

	return privateKeyBytes, nil
}

// GetPrivateKeyHexStr will convert private key to hex string format
func (k *RSAPairs) GetPrivateKeyHexStr() string {
	return hex.EncodeToString(k.PrivateKeyBytes)
}

// GetPublicKeyHexStr will convert public key to hex string format
func (k *RSAPairs) GetPublicKeyHexStr() string {
	return hex.EncodeToString(k.PublicKeyBytes)
}

// GetPrivateKeyBase64Str will convert private key to hex string format
func (k *RSAPairs) GetPrivateKeyBase64Str() string {
	return base64.StdEncoding.EncodeToString(k.PrivateKeyBytes)
}

// GetPublicKeyBase64Str will convert public key to hex string format
func (k *RSAPairs) GetPublicKeyBase64Str() string {
	return base64.StdEncoding.EncodeToString(k.PublicKeyBytes)
}

// LoadPrivateKey will load private key from bytes, format should be PKCS8
func LoadPrivateKey(privateKeyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyData)

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key data is not valid RSA private key data")
	}

	return privateKey, nil
}

// LoadPublicKey will load public key from bytes, format should be PKIX or ASN.1 DER
func LoadPublicKey(publicKeyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyData)

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("error: public key is not valid RSA Public Key")
	}

	return rsaPublicKey, nil
}

// LoadPrivateKeyFromBase64 will load private key from base64 bytes, format should be PKCS8
func LoadPrivateKeyFromBase64(privateKeyBase64Data []byte) (*rsa.PrivateKey, error) {
	privateKeyData := make([]byte, base64.StdEncoding.DecodedLen(len(privateKeyBase64Data)))
	n, err := base64.StdEncoding.Decode(privateKeyData, privateKeyBase64Data)
	if err != nil {
		return nil, err
	}

	privateKey, err := LoadPrivateKey(privateKeyData[:n])
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// LoadPublicKeyFromBase64 will load public key from bytes, format should be PKIX or ASN.1 DER
func LoadPublicKeyFromBase64(publicKeyBase64Data []byte) (*rsa.PublicKey, error) {
	publicKeyData := make([]byte, base64.StdEncoding.DecodedLen(len(publicKeyBase64Data)))
	n, err := base64.StdEncoding.Decode(publicKeyData, publicKeyBase64Data)
	if err != nil {
		return nil, err
	}

	publicKey, err := LoadPublicKey(publicKeyData[:n])
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

// LoadPrivateKeyAsBase64 will load private key from bytes
func LoadPrivateKeyAsBase64(privateKeyData []byte) (string, error) {
	privateKey, err := LoadPrivateKey(privateKeyData)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err := privateKeyToBytes(privateKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(privateKeyBytes), nil
}

// LoadPublicKeyAsBase64 will load public key from bytes
func LoadPublicKeyAsBase64(publicKeyData []byte) (string, error) {
	publicKey, err := LoadPublicKey(publicKeyData)
	if err != nil {
		return "", err
	}

	publicKeyBytes, err := publicKeyToBytes(publicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(publicKeyBytes), nil
}
