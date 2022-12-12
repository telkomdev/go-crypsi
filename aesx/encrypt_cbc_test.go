package aesx

import (
	"bytes"
	"encoding/hex"
	"strings"
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

// io

func TestEncryptWithAES128CBCIO(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES128CBCIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES128CBCIO should not returned error")
	}

	err = DecryptWithAES128CBCIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES128CBCIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES128CBCIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES192CBCIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES192CBCIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES192CBCIO should not returned error")
	}

	err = DecryptWithAES192CBCIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES192CBCIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES192CBCIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES256CBCIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES256CBCIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES256CBCIO should not returned error")
	}

	err = DecryptWithAES256CBCIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES256CBCIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES256CBCIO, plainDataOut should equal to expected")
	}
}
