package aesx

import (
	"encoding/hex"
	"testing"
)

func TestEncryptWithAES128GCM(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128GCM returned aesData should not nil")
	}
}

func TestEncryptWithAES192GCM(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192GCM returned aesData should not nil")
	}
}

func TestEncryptWithAES256GCM(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256GCM returned aesData should not nil")
	}
}
