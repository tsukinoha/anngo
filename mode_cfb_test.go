package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewCFB(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewCFB(b[:16])
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Mode: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "CFB" {
		t.Errorf("Mode Name: %v, Expected: %v", v.Name(), "CFB")
	}
}

func TestCFBEncrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 233},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 233, 61},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 176},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 176, 198},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 18},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			iv:       []byte("alouepc95malj23l"),
			expected: []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 18, 216},
		},
	}
	// Test
	for i, c := range cases {
		m := NewCFB(c.key)
		m.SetIV(c.iv)
		ret, _ := m.Encrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestCFBDecrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		iv       []byte
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 233},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{145, 86, 187, 56, 118, 10, 24, 235, 122, 241, 64, 43, 151, 39, 96, 24, 233, 61},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 176},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{87, 99, 218, 86, 155, 253, 158, 126, 114, 164, 1, 105, 132, 190, 159, 145, 176, 198},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 18},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{206, 141, 7, 202, 201, 112, 156, 138, 186, 58, 158, 167, 144, 146, 122, 9, 18, 216},
			iv:       []byte("alouepc95malj23l"),
			expected: []byte("abcdefghijklmnopqr"),
		},
	}
	// Test
	for i, c := range cases {
		m := NewCFB(c.key)
		m.SetIV(c.iv)
		ret, _ := m.Decrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestCFBIV(t *testing.T) {
	b := make([]byte, BlockSize)
	rand.Read(b)
	m := NewCFB(b[:BlockSize])
	if !bytes.Equal(m.iv, m.IV()) {
		t.Errorf("Result:   %v\nExpected: %v\n", m.IV(), m.iv)
	}
	// The returned IV must be a copy.
	orig := bytes.Clone(m.iv)
	m.IV()[0] ^= 0xff
	if !bytes.Equal(m.iv, orig) {
		t.Errorf("internal IV modified via IV()\nResult:   %v\nExpected: %v\n", m.iv, orig)
	}
}

func TestCFBSetIVInvalid(t *testing.T) {
	m := NewCFB(make([]byte, 16))
	orig := bytes.Clone(m.iv)
	for i, iv := range [][]byte{nil, make([]byte, 15), make([]byte, 17), make([]byte, 32)} {
		if err := m.SetIV(iv); err == nil {
			t.Errorf("\n<Case%d>\nExpected error for IV length %d\n", i, len(iv))
		}
		if !bytes.Equal(m.iv, orig) {
			t.Errorf("\n<Case%d>\nIV changed on error: %v\n", i, m.iv)
		}
	}
}

func TestCFBSetIV(t *testing.T) {
	// Case
	b := make([]byte, 128)
	rand.Read(b)
	cases := []struct {
		iv       []byte
		expected []byte
	}{
		{iv: b[:16], expected: b[:16]},
	}
	// Test
	m := NewCFB(b[16:32])
	for i, c := range cases {
		if err := m.SetIV(c.iv); err != nil {
			t.Errorf("\n<Case%d>\nError: %v\n", i, err)
		}
		if !bytes.Equal(m.iv, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, m.iv, c.expected)
		}
	}
}
