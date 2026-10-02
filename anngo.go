package anngo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	ErrInvalidPadding        = errors.New("invalid padding")
	ErrInvalidCiphertextSize = errors.New("ciphertext is not a multiple of the block size")
	errNotInitialized        = errors.New("mode is not initialized; use the New* constructor")
)

const (
	BlockSize int = aes.BlockSize
	AES128        = 16
	AES192        = 24
	AES256        = 32
)

type (
	padderInterface interface {
		Pad([]byte) []byte
		Unpad([]byte) ([]byte, error)
	}
	ModeInterface interface {
		Encrypt([]byte) ([]byte, error)
		Decrypt([]byte) ([]byte, error)
	}
	pkcs7Padding struct {
	}
	ansiX923Padding struct {
	}
	ECB struct {
		block    cipher.Block
		blockErr error
		padder   padderInterface
		macKey   []byte
	}
	CBC struct {
		block    cipher.Block
		blockErr error
		padder   padderInterface
		iv       []byte
		macKey   []byte
	}
	CFB struct {
		block    cipher.Block
		blockErr error
		iv       []byte
	}
	OFB struct {
		block    cipher.Block
		blockErr error
		iv       []byte
	}
	CTR struct {
		block    cipher.Block
		blockErr error
		iv       []byte
	}
)

func GenerateIV(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func copyIV(d, s []byte) error {
	if len(s) != BlockSize {
		return fmt.Errorf("IV size must be %d bytes", BlockSize)
	}
	if len(d) < len(s) {
		return fmt.Errorf("destination is less than source")
	}
	copy(d, s)
	return nil
}

// checkBlock reports why a mode cannot encrypt/decrypt. The cipher is created
// once in the constructor, so Encrypt/Decrypt only read shared state.
func checkBlock(block cipher.Block, err error) error {
	if err != nil {
		return err
	}
	if block == nil {
		return errNotInitialized
	}
	return nil
}
