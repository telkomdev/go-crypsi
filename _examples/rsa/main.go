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

	// asymmetric encryption with RSA
	plainData := "hello"

	encryptedData, err := rsax.EncryptWithOAEPSha256(publicKey, []byte(plainData))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	encryptedDataHex := hex.EncodeToString(encryptedData)
	fmt.Println(encryptedDataHex)

	// asymmetric decryption with RSA
	plainDataDecrypted, err := rsax.DecryptWithOAEPSha256(privateKey, encryptedData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(plainDataDecrypted))
}
