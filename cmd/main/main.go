package main

import (
	"fmt"
	"log"

	"github.com/po1nt-1/kleptoRSA/internal/rsa"
)

func main() {
	err := rsa.GenerateKeyPair(1024)
	if err != nil {
		log.Fatal(err)
	}

	publicKey, privateKey, err := rsa.Keys(1024)
	if err != nil {
		log.Fatal(err)
	}

	plainText := "Клептография	-	lorem ipsum dolor sit amet, ĉṓɲṩḙċťᶒțûɾ."
	cipherText, err := rsa.Encrypt(plainText, publicKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Cipher text:\t%v\n", cipherText.EncryptedContentInfo.EncryptedContent)

	decryptedText, err := rsa.Decrypt(cipherText, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted text:\t%v\n", decryptedText)
}
