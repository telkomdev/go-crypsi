package main

import (
	"fmt"
	"github.com/telkomdev/go-crypsi/aesx"
	"os"
)

func main() {
	key := []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	plainData := []byte("exampleplainte")

	aesData, err := aesx.EncryptWithAES256CBC(key, plainData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(aesData)
	fmt.Println(string(aesData))

	key = []byte("abc$#128djdyAgbjau&YAnmcbagryt5x")
	aesData = []byte("DEB31F3DF689EAE744EF60D765D16677011B1CC6C8964AD0080A7D981E838E79")
	plainDataDecrypted, err := aesx.DecryptWithAES256CBC(key, aesData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(plainDataDecrypted))
}
