package rsax

import (
	"testing"
)

func generateRSAPairs() (*RSAPairs, error) {
	return GenerateKeyPairs(KeySize4Kb)
}

func TestSignWithPSSMd5(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	signature, err := SignWithPSSMd5(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSMd5() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}
}

func TestSignWithPSSSha1(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	signature, err := SignWithPSSSha1(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha1() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}
}

func TestSignWithPSSSha256(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	signature, err := SignWithPSSSha256(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha256() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}
}

func TestSignWithPSSSha384(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	signature, err := SignWithPSSSha384(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha384() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}
}

func TestSignWithPSSSha512(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "hello"

	signature, err := SignWithPSSSha512(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha512() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}
}
