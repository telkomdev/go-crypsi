package main

import (
	"encoding/hex"
	"fmt"
	"github.com/telkomdev/go-crypsi/aesx"
	"os"
)

func main() {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plainData := []byte("exampleplaintext")

	aesData, err := aesx.EncryptWithAES128GCM(key, plainData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(aesData)
	fmt.Println(string(aesData))

	plainDataDecrypted, err := aesx.DecryptWithAES128GCM(key, aesData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(plainDataDecrypted))
}
