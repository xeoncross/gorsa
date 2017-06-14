# gorsa

A collection of RSA public/private key encryption helpers. These make working
with RSA keys easier. See the [example for usage](https://github.com/Xeoncross/gorsa/blob/master/example/main.go).

- https://golang.org/pkg/crypto/x509
- https://golang.org/pkg/crypto/rsa/
- https://golang.org/pkg/encoding/pem/
- https://github.com/cloudflare/cfssl/


## Example


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
