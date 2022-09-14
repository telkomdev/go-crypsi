package rsax

import (
	"testing"
)

func TestDecryptWithOAEPMd5(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPMd5(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPMd5() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPMd5(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPMd5() should succeed")
	}

	if string(plainData) != data {
		t.Error("error: plainData should equal to data")
	}
}

func TestDecryptWithOAEPSha1(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha1(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha1() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha1(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha1() should succeed")
	}

	if string(plainData) != data {
		t.Error("error: plainData should equal to data")
	}
}

func TestDecryptWithOAEPSha256(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha256(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha256() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha256(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha256() should succeed")
	}

	if string(plainData) != data {
		t.Error("error: plainData should equal to data")
	}
}

func TestDecryptWithOAEPSha384(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha384(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha384() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha384(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha384() should succeed")
	}

	if string(plainData) != data {
		t.Error("error: plainData should equal to data")
	}
}

func TestDecryptWithOAEPSha512(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha512(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha512() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha512(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha512() should succeed")
	}

	if string(plainData) != data {
		t.Error("error: plainData should equal to data")
	}
}

// ----------------------- test for invalid data -----------------------

func TestDecryptWithOAEPMd5WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPMd5(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPMd5() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPMd5(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPMd5() should succeed")
	}

	if string(plainData) == "ello" {
		t.Error("error: plainData should not equal to invalid data")
	}
}

func TestDecryptWithOAEPSha1WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha1(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha1() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha1(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha1() should succeed")
	}

	if string(plainData) == "ello" {
		t.Error("error: plainData should not equal to invalid data")
	}
}

func TestDecryptWithOAEPSha256WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha256(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha256() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha256(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha256() should succeed")
	}

	if string(plainData) == "ello" {
		t.Error("error: plainData should not equal to invalid data")
	}
}

func TestDecryptWithOAEPSha384WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha384(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha384() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha384(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha384() should succeed")
	}

	if string(plainData) == "ello" {
		t.Error("error: plainData should not equal to invalid data")
	}
}

func TestDecryptWithOAEPSha512WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	encryptedData, err := EncryptWithOAEPSha512(key.PublicKey, []byte(data))
	if err != nil {
		t.Error("error: EncryptWithOAEPSha512() should succeed")
	}

	if encryptedData == nil {
		t.Error("error: encryptedData should not be nil")
	}

	plainData, err := DecryptWithOAEPSha512(key.PrivateKey, encryptedData)
	if err != nil {
		t.Error("error: DecryptWithOAEPSha512() should succeed")
	}

	if string(plainData) == "ello" {
		t.Error("error: plainData should not equal to invalid data")
	}
}
