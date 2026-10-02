package anngo

import (
	"crypto/aes"
)

func NewECB(key []byte) *ECB {
	m := new(ECB)
	m.block, m.blockErr = aes.NewCipher(key)
	m.padder = pkcs7Padding{}
	return m
}

func (m *ECB) Pkcs7() {
	m.padder = pkcs7Padding{}
}

func (m *ECB) AnsiX923() {
	m.padder = ansiX923Padding{}
}

// HMAC enables Encrypt-then-MAC with HMAC-SHA256. Encrypt appends a
// MACSize-byte tag over the ciphertext, and Decrypt verifies it before
// removing the padding. Use a key independent of the encryption key.
func (m *ECB) HMAC(key []byte) error {
	k, err := newMACKey(key)
	if err != nil {
		return err
	}
	m.macKey = k
	return nil
}

func (m *ECB) Encrypt(s []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	src := m.padder.Pad(s)
	length := len(src)
	dst := make([]byte, length)
	for idx := 0; idx < length; idx += BlockSize {
		m.block.Encrypt(dst[idx:idx+BlockSize], src[idx:idx+BlockSize])
	}
	if m.macKey != nil {
		return appendMAC(m.macKey, nil, dst), nil
	}

	return dst, nil
}

func (m *ECB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	if m.macKey != nil {
		src, err = verifyMAC(m.macKey, nil, src)
		if err != nil {
			return nil, err
		}
	}
	length := len(src)
	if length == 0 || length%BlockSize != 0 {
		return nil, ErrInvalidCiphertextSize
	}
	dst := make([]byte, length)
	for idx := 0; idx < length; idx += BlockSize {
		m.block.Decrypt(dst[idx:idx+BlockSize], src[idx:idx+BlockSize])
	}
	return m.padder.Unpad(dst)
}
