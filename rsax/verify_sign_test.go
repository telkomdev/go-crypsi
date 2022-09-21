package rsax

import (
	"os"
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

// from io.Reader

func TestVerifySignWithPSSMd5IO(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	myFile, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile.Close() }()

	signature, err := SignWithPSSMd5IO(key.PrivateKey, myFile)
	if err != nil {
		t.Error("error: SignWithPSSMd5IO() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	// reopen the file
	myFile2, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile2.Close() }()

	err = VerifySignatureWithPSSMd5IO(key.PublicKey, signature, myFile2)
	if err != nil {
		t.Error("error: VerifySignatureWithPSSMd5IO() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha1IO(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	myFile, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile.Close() }()

	signature, err := SignWithPSSSha1IO(key.PrivateKey, myFile)
	if err != nil {
		t.Error("error: SignWithPSSSha1IO() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	// reopen the file
	myFile2, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile2.Close() }()

	err = VerifySignatureWithPSSSha1IO(key.PublicKey, signature, myFile2)
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha1IO() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha256IO(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	myFile, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile.Close() }()

	signature, err := SignWithPSSSha256IO(key.PrivateKey, myFile)
	if err != nil {
		t.Error("error: SignWithPSSSha256IO() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	// reopen the file
	myFile2, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile2.Close() }()

	err = VerifySignatureWithPSSSha256IO(key.PublicKey, signature, myFile2)
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha256IO() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha384IO(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	myFile, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile.Close() }()

	signature, err := SignWithPSSSha384IO(key.PrivateKey, myFile)
	if err != nil {
		t.Error("error: SignWithPSSSha384IO() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	// reopen the file
	myFile2, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile2.Close() }()

	err = VerifySignatureWithPSSSha384IO(key.PublicKey, signature, myFile2)
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha384IO() should succeed with valid data")
	}
}

func TestVerifySignWithPSSSha512IO(t *testing.T) {
	key, err := generateRSAPairs()

	if err != nil {
		t.Error("error: generateRSAPairs() should succeed")
	}

	myFile, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile.Close() }()

	signature, err := SignWithPSSSha512IO(key.PrivateKey, myFile)
	if err != nil {
		t.Error("error: SignWithPSSSha512IO() should succeed")
	}

	if signature == nil {
		t.Error("error: signature should not be nil")
	}

	// reopen the file
	myFile2, err := os.Open("./testdata/my_file.txt")
	if err != nil {
		t.Error("error: Open() should succeed")
	}

	defer func() { myFile2.Close() }()

	err = VerifySignatureWithPSSSha512IO(key.PublicKey, signature, myFile2)
	if err != nil {
		t.Error("error: VerifySignatureWithPSSSha512IO() should succeed with valid data")
	}
}
