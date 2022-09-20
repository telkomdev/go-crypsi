package aesx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecryptWithAES128GCM(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128GCM returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES128GCM(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES128GCM should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES128GCM: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES192GCM(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192GCM returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES192GCM(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES192GCM should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES192GCM: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256GCM(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256GCM returned aesData should not nil")
	}

	plainDataDecrypted, err := DecryptWithAES256GCM(key, aesData)
	if err != nil {
		t.Error("error: DecryptWithAES256GCM should not returned error")
	}

	if bytes.Compare(plainData, plainDataDecrypted) != 0 {
		t.Error("error: DecryptWithAES256GCM: plainData should equal to plainDataDecrypted")
	}
}

func TestDecryptWithAES256GCMWithInvalidCompare(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256GCM(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256GCM should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256GCM returned aesData should not nil")
	}

	invalidData := []byte("exampleplaintext1")

	if bytes.Compare(plainData, invalidData) == 0 {
		t.Error("error: plainData should not equal to invalidData")
	}
}
