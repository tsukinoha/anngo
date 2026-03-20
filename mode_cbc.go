package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCBC(key []byte) *CBC {
	m := new(CBC)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.padder = pkcs7Padding{}
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CBC) createBlock() error {
	if m.block != nil {
		return nil
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return err
	}
	m.block = block

	return nil
}

func (m *CBC) Pkcs7() {
	m.padder = pkcs7Padding{}
}

func (m *CBC) AnsiX923() {
	m.padder = ansiX923Padding{}
}

func (m *CBC) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	blockMode := cipher.NewCBCEncrypter(m.block, m.iv)
	text := m.padder.Pad(src)
	dst := make([]byte, len(text))
	blockMode.CryptBlocks(dst, text)

	return dst, nil
}

func (m *CBC) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	// BlockMode
	blockMode := cipher.NewCBCDecrypter(m.block, m.iv)
	d := make([]byte, len(src))
	blockMode.CryptBlocks(d, src)
	dst := m.padder.Unpad(d)

	return dst, nil
}

func (m *CBC) IV() []byte {
	return m.iv
}

func (m *CBC) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
