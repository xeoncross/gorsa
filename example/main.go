package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/xeoncross/gorsa"
)

/*
 * Generate an RSA keypair, then and save and reload them from files
 */

func main() {

	var password = "secretpassword"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// 1: Save without password encryption
	err = gorsa.SavePrivateKey("private.pem", *key, "")
	if err != nil {
		log.Fatal(err)
	}

	// 2: Save with password encryption
	err = gorsa.SavePrivateKey("private_password.pem", *key, password)
	if err != nil {
		log.Fatal(err)
	}

	// PublicKey
	publicKey := key.PublicKey

	// 1: Save public key in PKIX
	err = gorsa.SavePKIXPublicKey("public-1.pem", publicKey)
	if err != nil {
		log.Fatal(err)
	}
	// 2: Save in older ASN.1
	err = gorsa.SaveASN1PublicKey("public-2.pem", publicKey)
	if err != nil {
		log.Fatal(err)
	}

	var pub rsa.PublicKey

	// Read public key
	pub, err = gorsa.LoadPublicKeyFromFile("public-1.pem", "")
	if err != nil {
		log.Fatal(err)
	}

	// Read public key from private key
	pub, err = gorsa.LoadPublicKeyFromFile("private.pem", "")
	if err != nil {
		log.Fatal(err)
	}

	// Read public key from ENCRYPTED private key
	pub, err = gorsa.LoadPublicKeyFromFile("private_password.pem", password)
	if err != nil {
		log.Fatal(err)
	}

	if pub.E != publicKey.E {
		fmt.Println("Public Key Corruption!")
	}

}
