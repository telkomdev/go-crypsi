package rsax

import (
	"testing"
)

func TestVerifySignWithPSSMd5(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSMd5(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSMd5() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSMd5(key.PublicKey, signature, []byte(data))
	if err != nil {
		t.Error("error: VerifySignatureWithPSSMd5() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha1(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha1(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha1() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha1(key.PublicKey, signature, []byte(data))
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha1() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha256(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha256(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha256() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha256(key.PublicKey, signature, []byte(data))
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha256() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha384(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha384(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha384() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha384(key.PublicKey, signature, []byte(data))
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha384() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha512(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha512(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha512() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha512(key.PublicKey, signature, []byte(data))
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha512() should succeed with valid data")
	}
}

// ----------------------- test for invalid data -----------------------

func TestVerifySignWithPSSMd5WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSMd5(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSMd5() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSMd5(key.PublicKey, signature, []byte("elloworld"))
	if err == nil {
		t.Error("error: VerifySignatureWithPSSMd5() should error with invalid data")
	}
}

func TestVerifySignWithPSSSha1WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha1(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha1() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha1(key.PublicKey, signature, []byte("elloworld"))
	if err == nil {
		t.Error("error: VerifySignatureWithPSSSha1() should error with invalid data")
	}
}

func TestVerifySignWithPSSSha256WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha256(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha256() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha256(key.PublicKey, signature, []byte("elloworld"))
	if err == nil {
		t.Error("error: VerifySignatureWithPSSSha256() should error with invalid data")
	}
}

func TestVerifySignWithPSSSha384WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha384(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha384() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha384(key.PublicKey, signature, []byte("elloworld"))
	if err == nil {
		t.Error("error: VerifySignatureWithPSSSha384() should error with invalid data")
	}
}

func TestVerifySignWithPSSSha512WithInvalidData(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	data := "helloworld"

	signature, err := SignWithPSSSha512(key.PrivateKey, []byte(data))
	if err != nil {
		t.Error("error: SignWithPSSSha512() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	err = VerifySignatureWithPSSSha512(key.PublicKey, signature, []byte("elloworld"))
	if err == nil {
		t.Error("error: VerifySignatureWithPSSSha512() should error with invalid data")
	}
}
