package gorsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

/*
 * Collection of Go helpers for working with RSA keys
 */

// LoadPublicKey from a PEM encoded private (or public) key
func LoadPublicKey(pembytes []byte, password []byte) (pubkey rsa.PublicKey, err error) {
	pembytes = bytes.TrimSpace(pembytes)

	var block *pem.Block
	block, _ = pem.Decode(pembytes)
	if block == nil {
		err = errors.New("Invalid PEM key file")
		return
	}

	// Often needed for encrypted keys (i.e. SSH keys)
	if x509.IsEncryptedPEMBlock(block) {
		block, err = DecryptPEMBlock(block, password)
	}

	switch block.Type {

	// "BEGIN RSA (PUBLIC|PRIVATE) KEY" is PKCS#1, which can only contain RSA keys.
	// "BEGIN (PUBLIC|PRIVATE) KEY" is PKCS#8, which can contain a variety of formats.
	// "BEGIN ENCRYPTED PRIVATE KEY" is encrypted PKCS#8.

	case "PUBLIC KEY", "PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
		"RSA PUBLIC KEY", "RSA PRIVATE KEY":

		// PEM keys could be PKCS #1-#15, PKIX, elliptic curve, or another type
		var generalKey interface{}
		generalKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			generalKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				generalKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return
				}
			}
		}

		// We only support RSA keys
		switch generalKey := generalKey.(type) {
		case *rsa.PublicKey:
			pubkey = *generalKey
		case *rsa.PrivateKey:
			pubkey = generalKey.PublicKey
		// case *dsa.PublicKey: // todo
		// case *ecdsa.PublicKey: // todo
		default:
			err = fmt.Errorf("Unsupported key type %T", generalKey)
		}
	default:
		err = fmt.Errorf("Unsupported key type %q", block.Type)
	}

	return
}

// LoadPublicKeyFromFile given (expecting PEM format)
func LoadPublicKeyFromFile(filename string, password []byte) (pubkey rsa.PublicKey, err error) {
	var b []byte
	b, err = ioutil.ReadFile(filename)

	b = bytes.TrimSpace(b)

	return LoadPublicKey(b, password)
}

// DecryptPEMBlock using password (SSH keys are often encrypted)
func DecryptPEMBlock(block *pem.Block, password []byte) (out *pem.Block, err error) {

	if len(password) == 0 {
		err = errors.New("No password provided for encrypted PEM file")
		return
	}

	var der []byte
	der, err = x509.DecryptPEMBlock(block, password)
	if err != nil {
		return
	}

	return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}, nil
}

// // DecryptPEM if encrypted (SSH keys are often encrypted)
// func DecryptPEM(key []byte, password []byte) (out []byte, err error) {
// 	var block *pem.Block
// 	block, _ = pem.Decode(key)
//
// 	if x509.IsEncryptedPEMBlock(block) {
// 		if len(password) == 0 {
// 			err = errors.New("No password provided for encrypted PEM file")
// 			return
// 		}
//
// 		var der []byte
// 		der, err = x509.DecryptPEMBlock(block, password)
// 		if err != nil {
// 			return
// 		}
// 		key = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
// 	}
//
// 	return key, nil
// }
