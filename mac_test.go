package anngo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

type macMode interface {
	paddedMode
	HMAC([]byte) error
}

var macModeNames = []string{"CBC", "ECB"}

func newMACMode(t *testing.T, name string) macMode {
	t.Helper()
	m := newMode(name, []byte("0123456789abcdef")).(macMode)
	if err := m.HMAC([]byte("mac-key/0123456789abcdef")); err != nil {
		t.Fatalf("%s HMAC: %v", name, err)
	}
	return m
}

func TestHMACKey(t *testing.T) {
	for _, name := range macModeNames {
		for _, size := range []int{0, 1, MinMACKeySize - 1} {
			m := newMode(name, []byte("0123456789abcdef")).(macMode)
			if err := m.HMAC(make([]byte, size)); err != ErrInvalidMACKey {
				t.Errorf("%s key size %d\nResult:   %v\nExpected: %v", name, size, err, ErrInvalidMACKey)
			}
			// A rejected key must leave the MAC disabled.
			enc, _ := m.Encrypt([]byte("abc"))
			if len(enc) != BlockSize {
				t.Errorf("%s key size %d: MAC enabled by rejected key (len %d)", name, size, len(enc))
			}
		}
		for _, size := range []int{MinMACKeySize, 32, 64} {
			m := newMode(name, []byte("0123456789abcdef")).(macMode)
			if err := m.HMAC(make([]byte, size)); err != nil {
				t.Errorf("%s key size %d: %v", name, size, err)
			}
		}
	}
}

func TestHMACKeyIsCopied(t *testing.T) {
	for _, name := range macModeNames {
		key := []byte("mac-key/0123456789abcdef")
		m := newMode(name, []byte("0123456789abcdef")).(macMode)
		m.HMAC(key)
		enc, _ := m.Encrypt([]byte("abc"))
		key[0] ^= 0xff
		if _, err := m.Decrypt(enc); err != nil {
			t.Errorf("%s: key not copied: %v", name, err)
		}
	}
}

func TestHMACRoundTrip(t *testing.T) {
	for _, name := range macModeNames {
		for p, setPadding := range []func(paddedMode){paddedMode.Pkcs7, paddedMode.AnsiX923} {
			for n := 0; n <= BlockSize*3+1; n++ {
				m := newMACMode(t, name)
				setPadding(m)
				plain := bytes.Repeat([]byte{byte(n)}, n)
				enc, err := m.Encrypt(plain)
				if err != nil {
					t.Fatalf("%s/pad%d/len%d Encrypt error: %v", name, p, n, err)
				}
				padded := (n/BlockSize + 1) * BlockSize
				if len(enc) != padded+MACSize {
					t.Errorf("%s/pad%d/len%d length: %d, Expected: %d", name, p, n, len(enc), padded+MACSize)
					continue
				}
				dec, err := m.Decrypt(enc)
				if err != nil || !bytes.Equal(dec, plain) {
					t.Errorf("%s/pad%d/len%d Decrypt\nResult:   %v, %v\nExpected: %v", name, p, n, dec, err, plain)
				}
			}
		}
	}
}

// The tag must be HMAC-SHA256(macKey, IV || ciphertext) appended to the
// ciphertext produced without the MAC.
func TestHMACTag(t *testing.T) {
	macKey := []byte("mac-key/0123456789abcdef")
	plain := []byte("abcdefghijklmnopq")
	for _, name := range macModeNames {
		plainMode := newMode(name, []byte("0123456789abcdef"))
		m := newMode(name, []byte("0123456789abcdef")).(macMode)
		m.HMAC(macKey)
		var iv []byte
		if im, ok := plainMode.(ivMode); ok {
			iv = im.IV()
			m.(ivMode).SetIV(iv)
		}
		ct, _ := plainMode.Encrypt(plain)
		h := hmac.New(sha256.New, macKey)
		h.Write(iv)
		h.Write(ct)
		expected := h.Sum(ct)

		enc, _ := m.Encrypt(plain)
		if !bytes.Equal(enc, expected) {
			t.Errorf("%s\nResult:   %x\nExpected: %x", name, enc, expected)
		}
	}
}

// Any modification must be reported as ErrAuthentication, never as
// ErrInvalidPadding, so that no padding oracle is exposed.
func TestHMACTamper(t *testing.T) {
	plain := []byte("abcdefghijklmnopq")
	for _, name := range macModeNames {
		m := newMACMode(t, name)
		enc, _ := m.Encrypt(plain)

		for i := range enc {
			for _, bit := range []byte{0x01, 0x80} {
				c := bytes.Clone(enc)
				c[i] ^= bit
				if ret, err := m.Decrypt(c); err != ErrAuthentication {
					t.Errorf("%s flip byte %d bit %#x\nResult:   %v, %v\nExpected: %v", name, i, bit, ret, err, ErrAuthentication)
				}
			}
		}
		for _, n := range []int{0, 1, MACSize - 1, MACSize, MACSize + 1, len(enc) - 1} {
			if ret, err := m.Decrypt(enc[:n]); err != ErrAuthentication {
				t.Errorf("%s truncated to %d\nResult:   %v, %v\nExpected: %v", name, n, ret, err, ErrAuthentication)
			}
		}
		if ret, err := m.Decrypt(append(bytes.Clone(enc), 0x00)); err != ErrAuthentication {
			t.Errorf("%s extended\nResult:   %v, %v\nExpected: %v", name, ret, err, ErrAuthentication)
		}

		// Wrong MAC key.
		other := newMode(name, []byte("0123456789abcdef")).(macMode)
		other.HMAC([]byte("another-mac-key/0123456789"))
		syncIV(other, m)
		if ret, err := other.Decrypt(enc); err != ErrAuthentication {
			t.Errorf("%s wrong MAC key\nResult:   %v, %v\nExpected: %v", name, ret, err, ErrAuthentication)
		}

		// Ciphertext produced without the MAC.
		plainMode := newMode(name, []byte("0123456789abcdef"))
		syncIV(plainMode, m)
		ct, _ := plainMode.Encrypt(plain)
		if ret, err := m.Decrypt(ct); err != ErrAuthentication {
			t.Errorf("%s no tag\nResult:   %v, %v\nExpected: %v", name, ret, err, ErrAuthentication)
		}
	}
}

// The IV is covered by the tag, so decrypting with another IV must fail.
func TestHMACTamperIV(t *testing.T) {
	m := newMACMode(t, "CBC")
	enc, _ := m.Encrypt([]byte("abcdefghijklmnopq"))
	iv := m.(ivMode).IV()
	iv[0] ^= 0x01
	m.(ivMode).SetIV(iv)
	if ret, err := m.Decrypt(enc); err != ErrAuthentication {
		t.Errorf("Result:   %v, %v\nExpected: %v", ret, err, ErrAuthentication)
	}
}
