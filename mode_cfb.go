package anngo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCFB(key []byte) *CFB {
	m := new(CFB)
	m.block, m.blockErr = aes.NewCipher(key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CFB) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewCFBEncrypter(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CFB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewCFBDecrypter(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CFB) IV() []byte {
	return bytes.Clone(m.iv)
}

func (m *CFB) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
