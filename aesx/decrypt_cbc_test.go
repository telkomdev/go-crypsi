package aesx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecryptWithAES128CBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128CBC returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES128CBC(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES128CBC should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES128CBC: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES192CBC(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192CBC returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES192CBC(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES192CBC should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES192CBC: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256CBC(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CBC returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES256CBC(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES256CBC should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES256CBC: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256CBCWithInvalidCompare(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CBC returned aesData should not nil")
	}

	invalidData := []byte("exampleplaintext1")

	if bytes.Compare(plainData, invalidData) == 0 {
		t.Error("error: plainData should not equal to invalidData")
	}
}
