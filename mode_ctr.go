package anngo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func NewCTR(key []byte) *CTR {
	m := new(CTR)
	m.block, m.blockErr = aes.NewCipher(key)
	m.iv = make([]byte, BlockSize)
	rand.Read(m.iv)
	return m
}

func (m *CTR) Encrypt(src []byte) ([]byte, error) {
	// Block
	err := checkBlock(m.block, m.blockErr)
	if err != nil {
		return nil, err
	}
	// BlockMode
	dst := make([]byte, len(src))
	stream := cipher.NewCTR(m.block, m.iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func (m *CTR) Decrypt(src []byte) ([]byte, error) {
	return m.Encrypt(src)
}

func (m *CTR) IV() []byte {
	return bytes.Clone(m.iv)
}

func (m *CTR) SetIV(iv []byte) error {
	return copyIV(m.iv, iv)
}
