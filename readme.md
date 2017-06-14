# GoRSA

A collection of RSA public/private key encryption helpers. These make working
with RSA keys easier.

- https://golang.org/pkg/crypto/x509
- https://golang.org/pkg/crypto/rsa/
- https://golang.org/pkg/encoding/pem/
- https://github.com/cloudflare/cfssl/

# Install

    go get github.com/Xeoncross/gorsa

## Simple Example

    package main

    import (
    	"crypto/rand"
    	"crypto/rsa"
    	"log"

    	"github.com/xeoncross/gorsa"
    )

    func main() {

    	// Create RSA key
    	key, err := rsa.GenerateKey(rand.Reader, 2048)
    	if err != nil {
    		log.Fatal(err)
    	}

    	// Save with password encryption
    	err = gorsa.SavePrivateKey("private_password.pem", *key, "secretpassword")
    	if err != nil {
    		log.Fatal(err)
    	}

    	// Save public key
    	err = gorsa.SavePublicKey("public.pem", key.PublicKey)
    	if err != nil {
    		log.Fatal(err)
    	}

    }

For a complete demo, see [the example directory](https://github.com/Xeoncross/gorsa/blob/master/example/main.go).
