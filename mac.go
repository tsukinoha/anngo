// Encrypt-then-MAC with HMAC-SHA256
package anngo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

const (
	// MACSize is the size of the tag appended to the ciphertext.
	MACSize = sha256.Size
	// MinMACKeySize is the minimum length of the HMAC key.
	MinMACKeySize = 16
)

var (
	ErrAuthentication = errors.New("message authentication failed")
	ErrInvalidMACKey  = errors.New("HMAC key is too short")
)

func newMACKey(key []byte) ([]byte, error) {
	if len(key) < MinMACKeySize {
		return nil, ErrInvalidMACKey
	}
	return bytes.Clone(key), nil
}

func computeMAC(key, iv, ciphertext []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(iv)
	h.Write(ciphertext)
	return h.Sum(nil)
}

// appendMAC returns ciphertext || HMAC(key, iv || ciphertext).
func appendMAC(key, iv, ciphertext []byte) []byte {
	return append(ciphertext, computeMAC(key, iv, ciphertext)...)
}

// verifyMAC checks the tag in constant time and returns the ciphertext part.
func verifyMAC(key, iv, data []byte) ([]byte, error) {
	if len(data) < MACSize {
		return nil, ErrAuthentication
	}
	ciphertext, tag := data[:len(data)-MACSize], data[len(data)-MACSize:]
	if !hmac.Equal(tag, computeMAC(key, iv, ciphertext)) {
		return nil, ErrAuthentication
	}
	return ciphertext, nil
}
