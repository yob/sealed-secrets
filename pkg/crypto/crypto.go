package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	cloudkms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	sessionKeyBytes = 32
)

// ErrTooShort indicates the provided data is too short to be valid
var ErrTooShort = errors.New("SealedSecret data is too short")

// HybridEncrypt performs a regular AES-GCM + RSA-OAEP encryption.
// The output bytestring is:
//   RSA ciphertext length || RSA ciphertext || AES ciphertext
func HybridEncrypt(rnd io.Reader, pubKey *rsa.PublicKey, plaintext, label []byte) ([]byte, error) {
	// Generate a random symmetric key
	sessionKey := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(rnd, sessionKey); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt symmetric key
	rsaCiphertext, err := rsa.EncryptOAEP(sha256.New(), rnd, pubKey, sessionKey, nil)
	if err != nil {
		return nil, err
	}

	// First 2 bytes are RSA ciphertext length, so we can separate
	// all the pieces later.
	ciphertext := make([]byte, 2)
	binary.BigEndian.PutUint16(ciphertext, uint16(len(rsaCiphertext)))
	ciphertext = append(ciphertext, rsaCiphertext...)

	// SessionKey is only used once, so zero nonce is ok
	zeroNonce := make([]byte, aed.NonceSize())

	// Append symmetrically encrypted Secret
	ciphertext = aed.Seal(ciphertext, zeroNonce, plaintext, nil)

	return ciphertext, nil
}

// HybridDecrypt performs a regular AES-GCM + RSA-OAEP decryption
func HybridDecrypt(rnd io.Reader, keyName string, ciphertext, label []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, ErrTooShort
	}
	rsaLen := int(binary.BigEndian.Uint16(ciphertext))
	if len(ciphertext) < rsaLen+2 {
		return nil, ErrTooShort
	}

	rsaCiphertext := ciphertext[2 : rsaLen+2]
	aesCiphertext := ciphertext[rsaLen+2:]

	sessionKey, err := kmsAsyncDecrypt(keyName, rsaCiphertext)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aed, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Key is only used once, so zero nonce is ok
	zeroNonce := make([]byte, aed.NonceSize())

	plaintext, err := aed.Open(nil, zeroNonce, aesCiphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func kmsAsyncDecrypt(keyName string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	// Build the request.
	req := &kmspb.AsymmetricDecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	response, err := client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("decryption request failed: %+v", err)
	}
	return response.Plaintext, nil
}
