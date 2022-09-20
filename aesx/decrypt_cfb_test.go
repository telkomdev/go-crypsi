package aesx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecryptWithAES128CFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128CFB returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES128CFB(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES128CFB should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES128CFB: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES192CFB(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192CFB returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES192CFB(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES192CFB should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES192CFB: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256CFB(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CFB returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES256CFB(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES256CFB should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES256CFB: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256CFBWithInvalidCompare(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CFB returned aesData should not nil")
	}

	invalidData := []byte("exampleplaintext1")

	if bytes.Compare(plainData, invalidData) == 0 {
		t.Error("error: plainData should not equal to invalidData")
	}
}
