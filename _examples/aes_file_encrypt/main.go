package main

import (
	"encoding/hex"
	"fmt"
	"github.com/telkomdev/go-crypsi/aesx"
	"os"
)

func main() {
	// digital signature with RSA
	myFile, err := os.Open("Gopher.jpg")
	if err != nil {
		fmt.Println("error: open Gopher.jpg")
		os.Exit(1)
	}

	defer func() { myFile.Close() }()

	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")

	outputFile, err := os.Create("out.bin")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer func() { outputFile.Close() }()

	err = aesx.EncryptWithAES256GCMIO(key, myFile, outputFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
