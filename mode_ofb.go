package anngo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewOFB(key []byte) *OFB {
	m := new(OFB)
	m.block, m.blockErr = aes.NewCipher(key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *OFB) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewOFB(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *OFB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewOFB(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *OFB) IV() []byte {
	return bytes.Clone(m.iv)
}

func (m *OFB) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
