package gorsa

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// DecryptPEMBlock using password (SSH keys are often encrypted)
func DecryptPEMBlock(block *pem.Block, password string) (out *pem.Block, err error) {

	if password == "" {
		err = errors.New("No password provided for encrypted PEM file")
		return
	}

	var der []byte
	der, err = x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return
	}

	return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}, nil
}
