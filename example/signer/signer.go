package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/xeoncross/gorsa"
)

// SigningServer is a simple HTTP client + signing server.
// The message could be something like an app Serial Number.
// If the number is valid the server sends a signed request back.

var privateKeyPem = []byte(`-----BEGIN PRIVATE KEY-----
MIIEowIBAAKCAQEA3m86jWVtdWbDxuGplg/NmTbYhsprW01j4T1TXQ6pIYEWoS88
EPM8uQO/y/whd9nRFtu/CBpMIesP5PWIlIGzIeNIbpKHdG+VOl/bzot+rUFLuCUh
SSA7++noin/9PKdKMaWhAxytAIO1+/QX8BqEsiNGqzDV6y79jdWBRzFeb0NFMtH9
4ilezpYX2iKH5sQxN3kBethyGaOj8HLdQtm68ZqdH9pTePodU+jV2MImVGHqiAsx
QFEIvWes0jm/Aq00R9dFTD4R9YMdY2odGKCs6n+okwvO0QZ/qWWR8NhByewwih+g
6v5VKRNS1c9Inkyuqa0f7JWJahEIa6UeSbjRDwIDAQABAoIBAC1WYorbd5oMXi81
Y8mQYwmtoiinLYaomYkZZNp82IBZvXERHZ8e1OupFfjP5Up2fSW5mJBgO9BWByFV
4obSgN6RYvwWpcFX1QTW8QiCakmKG5LnDofHKDLKlHlWaRlpx7ei2NS3jZOjRP6b
3B02aoGcqxTNmWycYVX9hKIsL+FhZVah7wtbTAHn4sBq71RjqOluw+RsTJa8tUNT
3SQZUHZf5t2XjS9Kl58WKCOAv9zY1lbLocRQ9RxgPK5EgUCEg29jF630sbaXeo7I
Tj+A4tkHGcgjqbyU5U6cKhnCN3fga/lU8g8K4tPLojqkA6clk5GnWj1L9XgIvLKY
CGCoUZECgYEA/B7vfI7AxtVqV+pzv2wjRJ5qfept38alnQFKkyJsw4jmYnsaCwFO
vyi12cIEyEcknIB1ntGk/3M1yyZ6TcvoPn/dOkHSjlMqhl3NFm+pYBU4+jqPO5S6
L2VN8AhRQ+wjrE58c/ctu3zltwzUTKtNLR84hM6qExi5PKHss+0Q9g0CgYEA4dtd
Atp5R2u9FMCygYGphfhPiHKN5EB+KUbBjwE3kDHZHcDMzUL4ny5YrVQ9qsGGrqoP
1L4dRXqxkuUaj0hd7rEy+s6yMwqxfcvfi6pmmeBQ3G6JV1KOIHDVHiw13SGqi8nb
6hGAdObjtabms9R27P32MtlsANbW18w8cMm6GIsCgYEArexBVXG89u1ekQuBkbnt
knaeDALejRKiSO8NHPcQhMs58xHs406hnildWb0IQ4kgbn4HpeoFots9bsk6cdSK
gCMA4CFsORaSLWMkCag59bhuN+CR0o5E6lE+NKnoNaz+5uy12eHYQJBmf6JwCfva
H5h8CtHubYIOtw8VFQIjQzkCgYBT8nv8voWLdVEfMIxotG/1Gpk9Jw70QsBhySnS
ZGppjw2bEHlO5dCRIeHV8tTE7g+IRi+CLHOmynbMGZmongZD3NsM+9yiOhxEnI1n
VRuzn/uOIwurSEUJa8ba4yXWHlhMgufZdU3gpZ0HfJSNTLAzYCWtOsD5AuFx7jic
123zBwKBgGuTUp1ce4amjH6X5XmbVY8u5GDbHROVMLkBsCWNs/zVASGqsMEOLhO4
/C4iamjcfdjp9PA+Ik/J5fBG3eF3+i8hfTe1TAtKn9QyjjjdYw5+wy9JZZv/DTuE
7XZHxQasASz71Y2Uh+lB8nJheEauE+Uw7MtVomAYJUSq5GCDDvX2
-----END PRIVATE KEY-----`)

var publicKeyPem = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3m86jWVtdWbDxuGplg/N
mTbYhsprW01j4T1TXQ6pIYEWoS88EPM8uQO/y/whd9nRFtu/CBpMIesP5PWIlIGz
IeNIbpKHdG+VOl/bzot+rUFLuCUhSSA7++noin/9PKdKMaWhAxytAIO1+/QX8BqE
siNGqzDV6y79jdWBRzFeb0NFMtH94ilezpYX2iKH5sQxN3kBethyGaOj8HLdQtm6
8ZqdH9pTePodU+jV2MImVGHqiAsxQFEIvWes0jm/Aq00R9dFTD4R9YMdY2odGKCs
6n+okwvO0QZ/qWWR8NhByewwih+g6v5VKRNS1c9Inkyuqa0f7JWJahEIa6UeSbjR
DwIDAQAB
-----END PUBLIC KEY-----`)

func main() {

	var err error

	var bindToAddress = "127.0.0.1:9999"

	//
	// Step 1: Simple HTTP Server
	//

	// Server has the private key
	var key rsa.PrivateKey
	key, err = gorsa.LoadPrivateKey(privateKeyPem, "")
	if err != nil {
		log.Fatal(err)
	}

	h := http.NewServeMux()

	h.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {

		var input = strings.TrimSpace(r.FormValue("message"))
		fmt.Println("Client Sent:", input)

		// Probably need to lookup SN use count or account status
		if validateInput(input) == false {
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

		// Client has the server's public key
		var publicKey rsa.PublicKey
		publicKey, err = gorsa.LoadPublicKey(publicKeyPem, "")
		if err != nil {
			log.Fatal(err)
		}

		// No error means it's a valid signature
		err = gorsa.VerifyPKCS1v15([]byte(message), signature, publicKey)
		if err != nil {
			err = errors.New("Invalid Server Signature. MITM attack?")
			return
		}

		fmt.Println("Server Sent:", base64.StdEncoding.EncodeToString(signature))
		return
	}

	//
	// Step 3: Make some requests
	//

	// Valid Request
	err = makeRequest("1234-1234-1234-1234")
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

// In the real world this would probably request user info from the database
func validateInput(input string) bool {
	// Supper-high-tech-security
	return len(input) > 10
}
