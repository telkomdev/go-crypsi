package aesx

import (
	"bytes"
	"encoding/hex"
	"strings"
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

// io

func TestEncryptWithAES128GCMIO(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES128GCMIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES128GCMIO should not returned error")
	}

	err = DecryptWithAES128GCMIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES128GCMIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES128GCMIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES192GCMIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES192GCMIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES192GCMIO should not returned error")
	}

	err = DecryptWithAES192GCMIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES192GCMIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES192GCMIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES256GCMIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES256GCMIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES256GCMIO should not returned error")
	}

	err = DecryptWithAES256GCMIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES256GCMIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES256GCMIO, plainDataOut should equal to expected")
	}
}
