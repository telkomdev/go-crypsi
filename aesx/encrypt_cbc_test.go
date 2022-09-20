package aesx

import (
	"encoding/hex"
	"testing"
)

func TestEncryptWithAES128CBC(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128CBC returned aesData should not nil")
	}
}

func TestEncryptWithAES192CBC(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192CBC returned aesData should not nil")
	}
}

func TestEncryptWithAES256CBC(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CBC(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CBC should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CBC returned aesData should not nil")
	}
}
