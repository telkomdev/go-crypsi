package main

import (
	"encoding/hex"
	"fmt"
	"github.com/telkomdev/go-crypsi/rsax"
	"io/ioutil"
	"os"
)

func main() {
	// load private key from file
	privateKeyFile, err := os.Open("../../rsax/testdata/private.key")
	if err != nil {
		fmt.Println("error: open private.key")
		os.Exit(1)
	}

	defer func() { privateKeyFile.Close() }()

	privateKeyData, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		fmt.Println("error: ReadAll private.key")
		os.Exit(1)
	}

	privateKey, err := rsax.LoadPrivateKey(privateKeyData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// load public key from file
	publicKeyFile, err := os.Open("../../rsax/testdata/public.key")
	if err != nil {
		fmt.Println("error: open public.key")
		os.Exit(1)
	}

	defer func() { publicKeyFile.Close() }()

	publicKeyData, err := ioutil.ReadAll(publicKeyFile)
	if err != nil {
		fmt.Println("error: ReadAll public.key")
		os.Exit(1)
	}

	publicKey, err := rsax.LoadPublicKey(publicKeyData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// digital signature with RSA
	myFile, err := os.Open("my_file.txt")
	if err != nil {
		fmt.Println("error: open my_file.txt")
		os.Exit(1)
	}

	defer func() { myFile.Close() }()

	// signing
	signature, err := rsax.SignWithPSSSha256IO(privateKey, myFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// save this signature for example: to the database
	fmt.Println("signature: ", hex.EncodeToString(signature))

	// reopen the file
	myFile2, err := os.Open("my_file.txt")
	if err != nil {
		fmt.Println("error: open my_file.txt")
		os.Exit(1)
	}

	defer func() { myFile2.Close() }()

	// verifying signature
	err = rsax.VerifySignatureWithPSSSha256IO(publicKey, signature, myFile2)
	if err != nil {
		fmt.Println(err)
		fmt.Println("signature invalid")
	} else {
		fmt.Println("SIGNATURE VALID")
	}

	// ---------------------
	// signing

	myData := []byte("hello world")
	signature2, err := rsax.SignWithPSSSha256(privateKey, myData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// save this signature for example: to the database
	fmt.Println("signature: ", hex.EncodeToString(signature2))

	// verifying signature
	err = rsax.VerifySignatureWithPSSSha256(publicKey, signature2, myData)
	if err != nil {
		fmt.Println(err)
		fmt.Println("signature invalid")
	} else {
		fmt.Println("SIGNATURE VALID")
	}
}
