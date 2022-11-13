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
	myFile, err := os.Open("decrypted_file.bin")
	if err != nil {
		fmt.Println("error: open decrypted_file")
		os.Exit(1)
	}

	defer func() { myFile.Close() }()

	key, _ := hex.DecodeString("6368616e6765207468697320706173736368616e676520746869732070617373")
	decryptedData, err := io.ReadAll(myFile)
	if err != nil {
		fmt.Println("error: read all decrypted_file")
		os.Exit(1)
	}

	plainDataDecrypted, err := aesx.DecryptWithAES256GCM(key, decryptedData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	outputFile, err := os.Create("out.jpg")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer func() { outputFile.Close() }()

	_, err = outputFile.Write(plainDataDecrypted)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
