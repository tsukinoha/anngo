package anngo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCBC(key []byte) *CBC {
	m := new(CBC)
	m.block, m.blockErr = aes.NewCipher(key)
	m.padder = pkcs7Padding{}
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CBC) Pkcs7() {
	m.padder = pkcs7Padding{}
}

func (m *CBC) AnsiX923() {
	m.padder = ansiX923Padding{}
}

// HMAC enables Encrypt-then-MAC with HMAC-SHA256. Encrypt appends a
// MACSize-byte tag over the IV and ciphertext, and Decrypt verifies it before
// removing the padding. Use a key independent of the encryption key.
func (m *CBC) HMAC(key []byte) error {
	k, err := newMACKey(key)
	if err != nil {
		return err
	}
	m.macKey = k
	return nil
}

func (m *CBC) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	blockMode := cipher.NewCBCEncrypter(m.block, m.iv)
	text := m.padder.Pad(src)
	dst := make([]byte, len(text))
	blockMode.CryptBlocks(dst, text)
	if m.macKey != nil {
		return appendMAC(m.macKey, m.iv, dst), nil
	}

	return dst, nil
}

func (m *CBC) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	if m.macKey != nil {
		src, err = verifyMAC(m.macKey, m.iv, src)
		if err != nil {
			return nil, err
		}
	}
	if len(src) == 0 || len(src)%BlockSize != 0 {
		return nil, ErrInvalidCiphertextSize
	}
	// BlockMode
	blockMode := cipher.NewCBCDecrypter(m.block, m.iv)
	d := make([]byte, len(src))
	blockMode.CryptBlocks(d, src)

	return m.padder.Unpad(d)
}

func (m *CBC) IV() []byte {
	return bytes.Clone(m.iv)
}

func (m *CBC) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
