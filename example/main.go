package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/xeoncross/go-rsa"
)

/*
 * Generate an RSA keypair, then and save and reload them from files
 */

func main() {

	SigningServer()
	if true {
		return
	}

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

	fmt.Println(pub.E == publicKey.E)

	//
	// Signing tests
	//

	message := []byte("Hello World")
	var signature []byte

	signature, err = gorsa.SignPKCS1v15(message, *key)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(signature), signature)

}

// SigningServer is a simple HTTP server that signs requests
func SigningServer() {

	var err error

	var bindToAddress = "127.0.0.1:9999"

	// Message is used by both client and server. It represents something a Client
	// would send to the server and the server would verify and report back as
	// valid by signing it so the client knows the server validated it.
	var message = "password"

	var key rsa.PrivateKey
	key, err = gorsa.LoadPrivateKeyFromFile("private.pem", "")
	if err != nil {
		log.Fatal(err)
	}

	//
	// Step 1: Simple HTTP Server
	//

	h := http.NewServeMux()

	h.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {

		var input = strings.TrimSpace(r.FormValue("message"))
		fmt.Println("Client Sent:", input)

		// Here you would validate the input somehow
		if input != message {
			w.WriteHeader(400)
			w.Write([]byte("Bad request"))
			return
		}

		// Sign it to inform the client we validated it
		var signature []byte
		signature, err = gorsa.SignPKCS1v15([]byte(input), key)

		w.Write(signature)
		// w.Write([]byte("\n")) // Example extra whitespace
	})

	go func() {
		err = http.ListenAndServe(bindToAddress, h)
		log.Fatal(err)
	}()

	//
	// Step 2: Simple HTTP Client
	//

	var makeRequest = func(message string) (err error) {
		var data = url.Values{"message": []string{message}}

		res, err := http.PostForm("http://"+bindToAddress+"/sign", data)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Fatal(err)
		}

		if res.StatusCode != 200 {
			err = fmt.Errorf("%s: %s", res.Status, signature)
			return
		}

		// We aren't sending any extra whitespace, but your server might!
		signature = bytes.TrimSpace(signature)

		// No error means it's a valid signature
		err = gorsa.VerifyPKCS1v15([]byte(message), signature, key.PublicKey)
		if err != nil {
			err = errors.New("Invalid Server Signature. MITM attack?")
			return
		}

		fmt.Println("Server Sent:", base64.StdEncoding.EncodeToString(signature))
		return
	}

	// Valid Request
	err = makeRequest(message)
	if err != nil {
		fmt.Println("Verify Error:", err)
	} else {
		fmt.Println("Yay! Server validated our message!")
	}

	// Invalid Request
	err = makeRequest("foobar")
	if err != nil {
		fmt.Println("Verify Error:", err)
	} else {
		fmt.Println("Yay! Server validated our message!")
	}

}
