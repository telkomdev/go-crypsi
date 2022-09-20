package aesx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

type (
	AesAlg     string
	AesKeySize int
)

const (
	// Aes128KeySize the key size for AES 128 bit encryption
	Aes128KeySize AesKeySize = 16

	// Aes192KeySize the key size for AES 192 bit encryption
	Aes192KeySize AesKeySize = 24

	// Aes256KeySize the key size for AES 256 bit encryption
	Aes256KeySize AesKeySize = 32
)

const (
	// AesCBC the AES CBC mode
	AesCBC AesAlg = "cbc"

	// AesCFB the AES CFB mode
	AesCFB AesAlg = "cfb"

	// AesGCM the AES GCM mode
	AesGCM AesAlg = "gcm"
)

// AesData represent output from AES encryption
type AesData struct {
	CipherText string
	Nonce      string
}

// PKCS5Padding PKCS5 padding utility
func PKCS5Padding(plainText []byte) []byte {
	padding := (aes.BlockSize - len(plainText)%aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padtext...)
}

// PKCS5UnPadding PKCS5 unpadding utility
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func GenerateRandomIV(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	return b, nil
}

func isValidKeySize(key []byte) bool {
	keySizes := []AesKeySize{Aes128KeySize, Aes192KeySize, Aes256KeySize}
	for _, keySize := range keySizes {
		if len(key) == int(keySize) {
			return true
		}
	}

	return false
}

func encrypt(alg AesAlg, key []byte, plainData []byte) (*AesData, error) {
	if !isValidKeySize(key) {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var (
		cipherTextBytes []byte
		nonceBytes      []byte
	)

	switch alg {
	case AesCBC:
		// CBC mode works on blocks so plaintexts may need to be padded to the
		// next whole block. For an example of such padding, see
		// https://tools.ietf.org/html/rfc5246#section-6.2.3.2
		plainDataPadded := PKCS5Padding(plainData)
		cipherTextBytes = make([]byte, len(plainDataPadded))

		nonceBytes, err = GenerateRandomIV(block.BlockSize())
		if err != nil {
			return nil, err
		}

		mode := cipher.NewCBCEncrypter(block, nonceBytes)
		mode.CryptBlocks(cipherTextBytes, plainDataPadded)

		break
	case AesCFB:
		cipherTextBytes = make([]byte, len(plainData))

		nonceBytes, err = GenerateRandomIV(block.BlockSize())
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCFBEncrypter(block, nonceBytes)
		stream.XORKeyStream(cipherTextBytes, plainData)

		break
	case AesGCM:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonceBytes, err = GenerateRandomIV(aesGCM.NonceSize())
		if err != nil {
			return nil, err
		}

		cipherTextBytes = aesGCM.Seal(nil, nonceBytes, plainData, nil)

		break
	}

	return &AesData{
		CipherText: hex.EncodeToString(cipherTextBytes),
		Nonce:      hex.EncodeToString(nonceBytes),
	}, nil
}

func decrypt(alg AesAlg, key []byte, encryptedData *AesData) ([]byte, error) {
	if !isValidKeySize(key) {
		return nil, errors.New("invalid key size")
	}

	cipherTextBytes, err := hex.DecodeString(encryptedData.CipherText)
	if err != nil {
		return nil, err
	}

	nonceBytes, err := hex.DecodeString(encryptedData.Nonce)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var (
		plainDataBytes []byte
	)

	switch alg {
	case AesCBC:
		mode := cipher.NewCBCDecrypter(block, nonceBytes)
		mode.CryptBlocks(cipherTextBytes, cipherTextBytes)

		plainDataBytes = PKCS5UnPadding(cipherTextBytes)

		break
	case AesCFB:
		stream := cipher.NewCFBDecrypter(block, nonceBytes)
		stream.XORKeyStream(cipherTextBytes, cipherTextBytes)
		plainDataBytes = cipherTextBytes

		break
	case AesGCM:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		plainDataBytes, err = aesGCM.Open(nil, nonceBytes, cipherTextBytes, nil)
		if err != nil {
			return nil, err
		}

		break
	}

	return plainDataBytes, nil
}
