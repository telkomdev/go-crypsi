package aesx

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestEncryptWithAES128CFB(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES128CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES128CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES128CFB returned aesData should not nil")
	}
}

func TestEncryptWithAES192CFB(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES192CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES192CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES192CFB returned aesData should not nil")
	}
}

func TestEncryptWithAES256CFB(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	plainData := []byte("exampleplaintext")

	aesData, err := EncryptWithAES256CFB(key, plainData)
	if err != nil {
		t.Error("error: EncryptWithAES256CFB should not returned error")
	}

	if aesData == nil {
		t.Error("error: EncryptWithAES256CFB returned aesData should not nil")
	}
}

// io

func TestEncryptWithAES128CFBIO(t *testing.T) {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES128CFBIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES128CFBIO should not returned error")
	}

	err = DecryptWithAES128CFBIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES128CFBIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES128CFBIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES192CFBIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d40")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES192CFBIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES192CFBIO should not returned error")
	}

	err = DecryptWithAES192CFBIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES192CFBIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES192CFBIO, plainDataOut should equal to expected")
	}
}

func TestEncryptWithAES256CFBIO(t *testing.T) {
	key, _ := hex.DecodeString("48656c6c6f75656a656e6777656b67756538232461616d403534727475746965")
	expected := "exampleplaintext"
	plainDataIn := strings.NewReader(expected)

	var (
		encryptedDataOut bytes.Buffer
		plainDataOut     bytes.Buffer
	)

	err := EncryptWithAES256CFBIO(key, plainDataIn, &encryptedDataOut)
	if err != nil {
		t.Error("error: EncryptWithAES256CFBIO should not returned error")
	}

	err = DecryptWithAES256CFBIO(key, &encryptedDataOut, &plainDataOut)
	if err != nil {
		t.Error("error: DecryptWithAES256CFBIO should not returned error")
	}

	if plainDataOut.String() != expected {
		t.Error("error: DecryptWithAES256CFBIO, plainDataOut should equal to expected")
	}
}
