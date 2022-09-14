package rsax

import (
	"testing"
)

func TestEncryptWithOAEPMd5(t *testing.T) {
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
}

func TestEncryptWithOAEPSha1(t *testing.T) {
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
}

func TestEncryptWithOAEPSha256(t *testing.T) {
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
}

func TestEncryptWithOAEPSha384(t *testing.T) {
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
}

func TestEncryptWithOAEPSha512(t *testing.T) {
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
}
