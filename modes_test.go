package anngo

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type ivMode interface {
	ModeInterface
	IV() []byte
	SetIV([]byte) error
}

// syncIV copies the IV of src to dst when the mode uses one.
func syncIV(dst, src ModeInterface) {
	if s, ok := src.(ivMode); ok {
		dst.(ivMode).SetIV(s.IV())
	}
}

type paddedMode interface {
	ModeInterface
	Pkcs7()
	AnsiX923()
}

func newMode(name string, key []byte) ModeInterface {
	switch name {
	case "CBC":
		return NewCBC(key)
	case "CFB":
		return NewCFB(key)
	case "CTR":
		return NewCTR(key)
	case "ECB":
		return NewECB(key)
	case "OFB":
		return NewOFB(key)
	}
	panic("unknown mode: " + name)
}

var modeNames = []string{"CBC", "CFB", "CTR", "ECB", "OFB"}

// NIST SP 800-38A, Appendix F
var (
	nistPlain = mustHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	nistIV    = mustHex("000102030405060708090a0b0c0d0e0f")
	nistCtr   = mustHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	nistKey   = map[int][]byte{
		AES128: mustHex("2b7e151628aed2a6abf7158809cf4f3c"),
		AES192: mustHex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
		AES256: mustHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
	}
)

func TestNISTVectors(t *testing.T) {
	cases := []struct {
		mode     string
		keySize  int
		iv       []byte
		expected []byte
	}{
		{mode: "ECB", keySize: AES128, expected: mustHex("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4")},
		{mode: "ECB", keySize: AES192, expected: mustHex("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e")},
		{mode: "ECB", keySize: AES256, expected: mustHex("f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7")},
		{mode: "CBC", keySize: AES128, iv: nistIV, expected: mustHex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")},
		{mode: "CBC", keySize: AES256, iv: nistIV, expected: mustHex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")},
		{mode: "CFB", keySize: AES128, iv: nistIV, expected: mustHex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6")},
		{mode: "OFB", keySize: AES128, iv: nistIV, expected: mustHex("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e")},
		{mode: "CTR", keySize: AES128, iv: nistCtr, expected: mustHex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee")},
	}
	for i, c := range cases {
		m := newMode(c.mode, nistKey[c.keySize])
		if c.iv != nil {
			if err := m.(ivMode).SetIV(c.iv); err != nil {
				t.Fatalf("\n<Case%d %s>\nSetIV error: %v\n", i, c.mode, err)
			}
		}
		ret, err := m.Encrypt(nistPlain)
		if err != nil {
			t.Errorf("\n<Case%d %s>\nEncrypt error: %v\n", i, c.mode, err)
			continue
		}
		// ECB/CBC append one full padding block; the NIST vector is the prefix.
		if _, ok := m.(paddedMode); ok {
			if len(ret) != len(c.expected)+BlockSize {
				t.Errorf("\n<Case%d %s>\nLength: %d, Expected: %d\n", i, c.mode, len(ret), len(c.expected)+BlockSize)
				continue
			}
			ret = ret[:len(c.expected)]
		}
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d %s>\nResult:   %x\nExpected: %x\n", i, c.mode, ret, c.expected)
		}
		// Stream modes must also decrypt the raw NIST ciphertext.
		if _, ok := m.(paddedMode); !ok {
			dec, err := m.Decrypt(c.expected)
			if err != nil || !bytes.Equal(dec, nistPlain) {
				t.Errorf("\n<Case%d %s>\nDecrypt: %x, %v\nExpected: %x\n", i, c.mode, dec, err, nistPlain)
			}
		}
	}
}

func TestRoundTrip(t *testing.T) {
	iv := []byte("alouepc95malj23l")
	for _, name := range modeNames {
		for _, keySize := range []int{AES128, AES192, AES256} {
			key := bytes.Repeat([]byte{0x5a}, keySize)
			paddings := []func(paddedMode){nil}
			if _, ok := newMode(name, key).(paddedMode); ok {
				paddings = []func(paddedMode){paddedMode.Pkcs7, paddedMode.AnsiX923}
			}
			for p, setPadding := range paddings {
				for n := 0; n <= BlockSize*3+1; n++ {
					m := newMode(name, key)
					if setPadding != nil {
						setPadding(m.(paddedMode))
					}
					if im, ok := m.(ivMode); ok {
						im.SetIV(iv)
					}
					plain := bytes.Repeat([]byte{byte(n)}, n)
					enc, err := m.Encrypt(plain)
					if err != nil {
						t.Errorf("%s/%d/pad%d/len%d Encrypt error: %v", name, keySize, p, n, err)
						continue
					}
					if setPadding != nil {
						if len(enc)%BlockSize != 0 || len(enc) <= n {
							t.Errorf("%s/%d/pad%d/len%d bad ciphertext length: %d", name, keySize, p, n, len(enc))
						}
					} else if len(enc) != n {
						t.Errorf("%s/%d/len%d ciphertext length: %d, Expected: %d", name, keySize, n, len(enc), n)
					}
					// Encrypting twice with the same state must be deterministic.
					enc2, _ := m.Encrypt(plain)
					if !bytes.Equal(enc, enc2) {
						t.Errorf("%s/%d/pad%d/len%d Encrypt is not repeatable", name, keySize, p, n)
					}
					dec, err := m.Decrypt(enc)
					if err != nil || !bytes.Equal(dec, plain) {
						t.Errorf("%s/%d/pad%d/len%d Decrypt\nResult:   %v, %v\nExpected: %v", name, keySize, p, n, dec, err, plain)
					}
				}
			}
		}
	}
}

func TestInvalidKeySize(t *testing.T) {
	for _, name := range modeNames {
		for _, size := range []int{0, 1, 15, 17, 31, 33, 64} {
			m := newMode(name, make([]byte, size))
			if _, err := m.Encrypt([]byte("abc")); err == nil {
				t.Errorf("%s key size %d: Encrypt expected error", name, size)
			}
			if _, err := m.Decrypt(make([]byte, BlockSize)); err == nil {
				t.Errorf("%s key size %d: Decrypt expected error", name, size)
			}
		}
	}
}

func TestKeyIsCopied(t *testing.T) {
	plain := []byte("abcdefghijklmnopq")
	for _, name := range modeNames {
		key := []byte("0123456789abcdef")
		m := newMode(name, key)
		enc, _ := m.Encrypt(plain)
		key[0] ^= 0xff
		m2 := newMode(name, []byte("0123456789abcdef"))
		syncIV(m2, m)
		enc2, _ := m2.Encrypt(plain)
		if !bytes.Equal(enc, enc2) {
			t.Errorf("%s: key not copied", name)
		}
	}
}

func TestBlockModeInvalidCiphertextSize(t *testing.T) {
	for _, name := range []string{"CBC", "ECB"} {
		for _, size := range []int{0, 1, 15, 17, 31, 33} {
			m := newMode(name, []byte("0123456789abcdef"))
			ret, err := m.Decrypt(make([]byte, size))
			if err != ErrInvalidCiphertextSize {
				t.Errorf("%s size %d\nResult:   %v, %v\nExpected: %v", name, size, ret, err, ErrInvalidCiphertextSize)
			}
		}
	}
}

func TestBlockModeInvalidPadding(t *testing.T) {
	plain := []byte("abcdefghijklmn")
	for _, name := range []string{"CBC", "ECB"} {
		// Wrong key: the decrypted padding is garbage.
		m := newMode(name, []byte("0123456789abcdef"))
		enc, _ := m.Encrypt(plain)
		wrong := newMode(name, []byte("fedcba9876543210"))
		syncIV(wrong, m)
		if ret, err := wrong.Decrypt(enc); err != ErrInvalidPadding {
			t.Errorf("%s wrong key\nResult:   %v, %v\nExpected: %v", name, ret, err, ErrInvalidPadding)
		}

		// PKCS#7 padding "0e 0e ... 0e" is not valid ANSI X9.23 padding.
		ansi := newMode(name, []byte("0123456789abcdef")).(paddedMode)
		ansi.AnsiX923()
		syncIV(ansi, m)
		if ret, err := ansi.Decrypt(enc); err != ErrInvalidPadding {
			t.Errorf("%s padding mismatch\nResult:   %v, %v\nExpected: %v", name, ret, err, ErrInvalidPadding)
		}
	}
}

func TestEncryptDoesNotModifySource(t *testing.T) {
	for _, name := range modeNames {
		buf := []byte("0123456789abcdefghijklmnopqrstuv")
		orig := bytes.Clone(buf)
		m := newMode(name, []byte("0123456789abcdef"))
		m.Encrypt(buf[:10])
		if !bytes.Equal(buf, orig) {
			t.Errorf("%s: source modified\nResult:   %v\nExpected: %v", name, buf, orig)
		}
	}
}

func TestNewIVIsRandom(t *testing.T) {
	key := []byte("0123456789abcdef")
	for _, name := range []string{"CBC", "CFB", "CTR", "OFB"} {
		a := newMode(name, key).(ivMode).IV()
		b := newMode(name, key).(ivMode).IV()
		if len(a) != BlockSize || bytes.Equal(a, b) {
			t.Errorf("%s: IV not random\n  %v\n  %v", name, a, b)
		}
	}
}

// A single instance must be usable from multiple goroutines (run with -race).
func TestConcurrentUse(t *testing.T) {
	plain := []byte("abcdefghijklmnopq")
	for _, name := range modeNames {
		newShared := func() ModeInterface {
			m := newMode(name, []byte("0123456789abcdef"))
			if mm, ok := m.(macMode); ok {
				mm.HMAC([]byte("mac-key/0123456789abcdef"))
			}
			return m
		}
		// Compute the expected value on another instance so that the shared
		// one is first used from the goroutines.
		ref := newShared()
		m := newShared()
		syncIV(m, ref)
		expected, _ := ref.Encrypt(plain)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 50 {
					enc, err := m.Encrypt(plain)
					if err != nil || !bytes.Equal(enc, expected) {
						t.Errorf("%s Encrypt: %v, %v", name, enc, err)
						return
					}
					dec, err := m.Decrypt(enc)
					if err != nil || !bytes.Equal(dec, plain) {
						t.Errorf("%s Decrypt: %v, %v", name, dec, err)
						return
					}
				}
			})
		}
		wg.Wait()
	}
}

// Zero values (not created by New*) must return an error instead of panicking.
func TestZeroValue(t *testing.T) {
	for _, m := range []ModeInterface{new(CBC), new(CFB), new(CTR), new(ECB), new(OFB)} {
		if _, err := m.Encrypt([]byte("abc")); err == nil {
			t.Errorf("%T Encrypt: expected error", m)
		}
		if _, err := m.Decrypt(make([]byte, BlockSize)); err == nil {
			t.Errorf("%T Decrypt: expected error", m)
		}
	}
}
