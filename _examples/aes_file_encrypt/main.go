package main

import (
	"encoding/hex"
	"fmt"
	"github.com/telkomdev/go-crypsi/aesx"
	"io"
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
	plainData, err := io.ReadAll(myFile)
	if err != nil {
		fmt.Println("error: read all Gopher.jpg")
		os.Exit(1)
	}

	aesData, err := aesx.EncryptWithAES256GCM(key, plainData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	outputFile, err := os.Create("out.bin")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer func() { outputFile.Close() }()

	_, err = outputFile.Write(aesData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
