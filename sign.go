package gorsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

/*
 * PKCS#1, "the" RSA standard, describes how a signature should be encoded, and
 * it is a sequence of bytes with big-endian unsigned encoding, always of the size
 * of the modulus. For a 2048-bit modulus, all signatures have length exactly 256
 * bytes.
 */

// SignPKCS1v15 message
func SignPKCS1v15(message []byte, privateKey rsa.PrivateKey) (signature []byte, err error) {
	// message := []byte("message to be signed")

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)

	signature, err = rsa.SignPKCS1v15(rand.Reader, &privateKey, crypto.SHA256, hashed[:])

	return
}

// VerifyPKCS1v15 message
func VerifyPKCS1v15(message []byte, signature []byte, publicKey rsa.PublicKey) (err error) {
	// message := []byte("message to be signed")

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed. This requires
	// that the hash function be collision resistant. SHA-256 is the
	// least-strong hash function that should be used for this at the time
	// of writing (2016).
	hashed := sha256.Sum256(message)

	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed[:], signature)

	return
}
