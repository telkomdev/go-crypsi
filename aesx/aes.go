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
	// AesAlg the AES mode algorithm defined type
	AesAlg string

	// AesKeySize the AES key size defined type
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

// PKCS5Padding PKCS5 padding utility
func PKCS5Padding(plainText []byte) []byte {
	padding := (aes.BlockSize - len(plainText)%aes.BlockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padtext...)
}

// PKCS5UnPadding PKCS5 unpadding utility
func PKCS5UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	unpadding = length - unpadding
	if unpadding <= 0 {
		return nil, errors.New("invalid encrypted data or key")
	}
	return src[:unpadding], nil
}

func GenerateRandomIV(b []byte) error {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return err
	}

	return nil
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

func encrypt(alg AesAlg, key []byte, plainData []byte) ([]byte, error) {
	if !isValidKeySize(key) {
		return nil, errors.New("invalid key size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch alg {
	case AesCBC:
		// CBC mode works on blocks so plaintexts may need to be padded to the
		// next whole block. For an example of such padding, see
		// https://tools.ietf.org/html/rfc5246#section-6.2.3.2
		plainDataPadded := PKCS5Padding(plainData)
		cipherDataBytes := make([]byte, len(plainDataPadded)+aes.BlockSize)

		err = GenerateRandomIV(cipherDataBytes[:aes.BlockSize])
		if err != nil {
			return nil, err
		}

		mode := cipher.NewCBCEncrypter(block, cipherDataBytes[:aes.BlockSize])
		mode.CryptBlocks(cipherDataBytes[aes.BlockSize:], plainDataPadded)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)
		return dst, nil
	case AesCFB:
		cipherDataBytes := make([]byte, len(plainData)+block.BlockSize())

		err = GenerateRandomIV(cipherDataBytes[:block.BlockSize()])
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCFBEncrypter(block, cipherDataBytes[:block.BlockSize()])
		stream.XORKeyStream(cipherDataBytes[block.BlockSize():], plainData)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)
		return dst, nil
	case AesGCM:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		cipherDataBytes := make([]byte, len(plainData)+aesGCM.NonceSize())

		err = GenerateRandomIV(cipherDataBytes[:aesGCM.NonceSize()])
		if err != nil {
			return nil, err
		}

		res := aesGCM.Seal(nil, cipherDataBytes[:aesGCM.NonceSize()], plainData, nil)
		cipherDataBytes = append(cipherDataBytes[:aesGCM.NonceSize()], res...)

		dst := make([]byte, hex.EncodedLen(len(cipherDataBytes)))
		hex.Encode(dst, cipherDataBytes)
		return dst, nil
	}

	return nil, errors.New("encrypt process failed")
}

func decrypt(alg AesAlg, key []byte, encryptedData []byte) ([]byte, error) {
	if !isValidKeySize(key) {
		return nil, errors.New("invalid key size")
	}

	encryptedDataOut := make([]byte, hex.DecodedLen(len(encryptedData)))
	encryptedDataOutN, err := hex.Decode(encryptedDataOut, encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	switch alg {
	case AesCBC:
		if len(encryptedDataOut) < aes.BlockSize {
			return nil, errors.New("encrypted data too short")
		}

		cipherDataBytes := encryptedDataOut[:encryptedDataOutN][aes.BlockSize:]
		if len(cipherDataBytes)%aes.BlockSize != 0 {
			return nil, errors.New("invalid padding: encrypted data is not a multiple of the block size")
		}

		nonceBytes := encryptedDataOut[:encryptedDataOutN][:aes.BlockSize]

		mode := cipher.NewCBCDecrypter(block, nonceBytes)
		mode.CryptBlocks(cipherDataBytes, cipherDataBytes)

		cipherDataBytes, err = PKCS5UnPadding(cipherDataBytes)
		if err != nil {
			return nil, errors.New("invalid encrypted data or key")
		}
		return cipherDataBytes, nil
	case AesCFB:
		cipherDataBytes := encryptedDataOut[:encryptedDataOutN][aes.BlockSize:]
		nonceBytes := encryptedDataOut[:encryptedDataOutN][:aes.BlockSize]

		stream := cipher.NewCFBDecrypter(block, nonceBytes)
		stream.XORKeyStream(cipherDataBytes, cipherDataBytes)
		return cipherDataBytes, nil
	case AesGCM:
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		cipherDataBytes := encryptedDataOut[:encryptedDataOutN][aesGCM.NonceSize():]
		nonceBytes := encryptedDataOut[:encryptedDataOutN][:aesGCM.NonceSize()]

		plainDataBytes, err := aesGCM.Open(nil, nonceBytes, cipherDataBytes, nil)
		if err != nil {
			return nil, err
		}

		return plainDataBytes, nil
	}

	return nil, errors.New("decrypt process failed")
}
