package anngo

import (
	"crypto/aes"
)

func NewECB(key []byte) *ECB {
	m := new(ECB)
	m.key = make([]byte, len(key))
	copy(m.key, key)
	m.padder = pkcs7Padding{}
	return m
}

func (m *ECB) createBlock() error {
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

func (m *ECB) Pkcs7() {
	m.padder = pkcs7Padding{}
}

func (m *ECB) AnsiX923() {
	m.padder = ansiX923Padding{}
}

func (m *ECB) Encrypt(s []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	src := m.padder.Pad(s)
	length := len(src)
	dst := make([]byte, length)
	for i := 0; i*BlockSize < length; i++ {
		idx := i * BlockSize
		max := idx + BlockSize
		if max > length {
			max = length
		}
		m.block.Encrypt(dst[idx:max], src[idx:max])
	}

	return dst, err
}

func (m *ECB) Decrypt(src []byte) ([]byte, error) {
	// Block
	err := m.createBlock()
	if err != nil {
		return nil, err
	}
	length := len(src)
	dst := make([]byte, length)
	for i := 0; i*BlockSize < length; i++ {
		idx := i * BlockSize
		max := idx + BlockSize
		if max > length {
			max = length
		}
		m.block.Decrypt(dst[idx:max], src[idx:max])
	}
	d := m.padder.Unpad(dst)
	return d, err
}
