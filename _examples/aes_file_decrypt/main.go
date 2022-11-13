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
		fmt.Println("error: open my_file.txt")
		os.Exit(1)
	}

	defer func() { myFile.Close() }()

	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	decryptedData, err := io.ReadAll(myFile)
	if err != nil {
		fmt.Println("error: read all my_file.txt")
		os.Exit(1)
	}

	plainDataDecrypted, err := aesx.DecryptWithAES128GCM(key, decryptedData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	outputFile, err := os.Create("out.txt")
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
