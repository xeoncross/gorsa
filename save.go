package gorsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
)

// SavePKIXPublicKey to the given fileName
func SavePKIXPublicKey(fileName string, key *rsa.PublicKey) (err error) {
	var b []byte
	b, err = x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		return
	}

	var block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}

	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	return
}

// SaveASN1PublicKey to the given fileName
func SaveASN1PublicKey(fileName string, key *rsa.PublicKey) (err error) {
	var b []byte
	b, err = asn1.Marshal(key)
	if err != nil {
		return
	}

	var block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}

	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	return
}

// SavePKCS1PrivateKey to the given filepath
func SavePKCS1PrivateKey(fileName string, key *rsa.PrivateKey, password string) (err error) {

	var block = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	// Encrypt the PEM?
	if password != "" {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return
		}
	}

	err = ioutil.WriteFile(fileName, pem.EncodeToMemory(block), 0600)
	return
}

// SavePKCS8PrivateKey to the given filepath
// Go doesn't support PKCS#8 natively
// TODO fix this
func SavePKCS8PrivateKey(fileName string, key *rsa.PrivateKey, password string) (err error) {

	pkcs8Key := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{
		Version:    0,
		PrivateKey: x509.MarshalPKCS1PrivateKey(key),
	}

	pkcs8Key.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	pkcs8Key.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	var b []byte
	b, err = asn1.Marshal(pkcs8Key)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fileName, b, 0600)
	return
}
