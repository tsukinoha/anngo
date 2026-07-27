package anngo

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

func TestNewECB(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewECB(b[:16])
	v := reflect.TypeOf(m)
	if v.Kind() != reflect.Pointer {
		t.Errorf("Mode: %v, Expected: %v", v.Kind(), reflect.Pointer)
	} else if v.Elem().Name() != "ECB" {
		t.Errorf("Mode Name: %v, Expected: %v", v.Name(), "ECB")
	}
}

func TestECBPkcs7(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewECB(b[:16])
	m.padder = pkcs7Padding{}
	m.Pkcs7()
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("Result: %s, Expected: %s", typ, "pkcs7Padding")
	}
}

func TestECBAnsiX923(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	m := NewECB(b[:16])
	typ := reflect.TypeOf(m.padder).Name()
	if typ != "pkcs7Padding" {
		t.Errorf("not ready yet")
	}
	m.AnsiX923()
	typ = reflect.TypeOf(m.padder).Name()
	if typ != "ansiX923Padding" {
		t.Errorf("Result: %s, Expected: %s", typ, "ansiX923Padding")
	}
}

func TestECBEncrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		padder   padderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			padder:   pkcs7Padding{},
			expected: []byte{55, 21, 77, 54, 24, 109, 250, 166, 56, 152, 91, 46, 107, 97, 56, 134},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			padder:   pkcs7Padding{},
			expected: []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			padder:   pkcs7Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 55, 114, 34, 224, 97, 169, 36, 197, 145, 205, 156, 39, 234, 22, 62, 212},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   pkcs7Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 199, 82, 84, 255, 34, 17, 34, 147, 205, 245, 192, 29, 244, 124, 68, 51},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   pkcs7Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 75, 163, 126, 99, 191, 217, 232, 162, 241, 121, 251, 177, 126, 74, 145, 220},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmn"),
			padder:   ansiX923Padding{},
			expected: []byte{238, 29, 43, 26, 117, 109, 105, 9, 180, 105, 203, 171, 104, 235, 183, 82},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmno"),
			padder:   ansiX923Padding{},
			expected: []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnop"),
			padder:   ansiX923Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 223, 37, 244, 191, 78, 66, 80, 147, 189, 189, 226, 181, 75, 41, 204, 236},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   ansiX923Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 52, 223, 69, 58, 172, 38, 192, 74, 146, 67, 102, 47, 198, 99, 117, 100},
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   ansiX923Padding{},
			expected: []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 204, 194, 38, 117, 173, 28, 94, 231, 246, 167, 239, 8, 75, 91, 124, 130},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			padder:   pkcs7Padding{},
			expected: []byte{204, 148, 233, 40, 238, 195, 248, 21, 162, 8, 190, 215, 182, 16, 108, 0},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			padder:   pkcs7Padding{},
			expected: []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			padder:   pkcs7Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 3, 102, 117, 172, 27, 118, 83, 91, 199, 54, 56, 96, 195, 102, 146, 105},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   pkcs7Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 60, 170, 41, 177, 133, 79, 181, 24, 155, 44, 59, 226, 97, 120, 164, 136},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   pkcs7Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 223, 113, 2, 50, 212, 171, 241, 193, 192, 14, 10, 213, 214, 110, 201, 5},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmn"),
			padder:   ansiX923Padding{},
			expected: []byte{200, 116, 77, 188, 227, 83, 254, 239, 35, 222, 151, 98, 254, 132, 63, 9},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmno"),
			padder:   ansiX923Padding{},
			expected: []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnop"),
			padder:   ansiX923Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 35, 68, 27, 126, 31, 235, 121, 123, 210, 161, 16, 44, 85, 207, 68, 158},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   ansiX923Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 222, 40, 224, 165, 70, 37, 112, 6, 39, 174, 31, 26, 127, 40, 49, 246},
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   ansiX923Padding{},
			expected: []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 13, 161, 125, 73, 179, 158, 186, 46, 177, 199, 195, 74, 79, 56, 189, 163},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			padder:   pkcs7Padding{},
			expected: []byte{125, 143, 121, 9, 127, 221, 251, 238, 232, 218, 225, 174, 152, 88, 63, 196},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			padder:   pkcs7Padding{},
			expected: []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			padder:   pkcs7Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 204, 161, 137, 114, 125, 62, 36, 179, 84, 10, 8, 168, 144, 169, 66, 83},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   pkcs7Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 142, 222, 157, 213, 110, 182, 24, 122, 107, 57, 185, 144, 211, 163, 120, 33},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   pkcs7Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 252, 18, 148, 68, 155, 1, 169, 179, 205, 164, 133, 86, 121, 70, 34, 236},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmn"),
			padder:   ansiX923Padding{},
			expected: []byte{141, 103, 78, 66, 218, 130, 83, 62, 203, 25, 178, 58, 13, 12, 22, 213},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmno"),
			padder:   ansiX923Padding{},
			expected: []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnop"),
			padder:   ansiX923Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 129, 37, 158, 98, 203, 91, 236, 56, 191, 68, 48, 174, 5, 233, 147, 42},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopq"),
			padder:   ansiX923Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 231, 85, 177, 1, 69, 253, 47, 38, 93, 178, 187, 133, 218, 155, 46, 111},
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte("abcdefghijklmnopqr"),
			padder:   ansiX923Padding{},
			expected: []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 155, 157, 107, 85, 209, 89, 135, 151, 183, 184, 162, 69, 249, 118, 33, 213},
		},
	}
	// Test
	for i, c := range cases {
		m := NewECB(c.key)
		m.padder = c.padder
		ret, _ := m.Encrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}

func TestECBDecrypt(t *testing.T) {
	// Case
	cases := []struct {
		key      []byte
		data     []byte
		padder   padderInterface
		expected []byte
	}{
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{55, 21, 77, 54, 24, 109, 250, 166, 56, 152, 91, 46, 107, 97, 56, 134},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 55, 114, 34, 224, 97, 169, 36, 197, 145, 205, 156, 39, 234, 22, 62, 212},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 199, 82, 84, 255, 34, 17, 34, 147, 205, 245, 192, 29, 244, 124, 68, 51},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 75, 163, 126, 99, 191, 217, 232, 162, 241, 121, 251, 177, 126, 74, 145, 220},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{238, 29, 43, 26, 117, 109, 105, 9, 180, 105, 203, 171, 104, 235, 183, 82},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{205, 215, 47, 196, 28, 56, 247, 118, 68, 155, 191, 77, 166, 186, 198, 250},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 223, 37, 244, 191, 78, 66, 80, 147, 189, 189, 226, 181, 75, 41, 204, 236},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 52, 223, 69, 58, 172, 38, 192, 74, 146, 67, 102, 47, 198, 99, 117, 100},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdef"),
			data:     []byte{133, 98, 125, 240, 69, 30, 119, 64, 235, 38, 11, 29, 241, 244, 252, 100, 204, 194, 38, 117, 173, 28, 94, 231, 246, 167, 239, 8, 75, 91, 124, 130},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{204, 148, 233, 40, 238, 195, 248, 21, 162, 8, 190, 215, 182, 16, 108, 0},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 3, 102, 117, 172, 27, 118, 83, 91, 199, 54, 56, 96, 195, 102, 146, 105},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 60, 170, 41, 177, 133, 79, 181, 24, 155, 44, 59, 226, 97, 120, 164, 136},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 223, 113, 2, 50, 212, 171, 241, 193, 192, 14, 10, 213, 214, 110, 201, 5},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{200, 116, 77, 188, 227, 83, 254, 239, 35, 222, 151, 98, 254, 132, 63, 9},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{34, 206, 80, 92, 182, 165, 35, 191, 10, 224, 158, 170, 168, 52, 189, 161},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 35, 68, 27, 126, 31, 235, 121, 123, 210, 161, 16, 44, 85, 207, 68, 158},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 222, 40, 224, 165, 70, 37, 112, 6, 39, 174, 31, 26, 127, 40, 49, 246},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmn"),
			data:     []byte{113, 72, 25, 82, 152, 93, 166, 203, 12, 33, 238, 221, 141, 246, 82, 154, 13, 161, 125, 73, 179, 158, 186, 46, 177, 199, 195, 74, 79, 56, 189, 163},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{125, 143, 121, 9, 127, 221, 251, 238, 232, 218, 225, 174, 152, 88, 63, 196},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 204, 161, 137, 114, 125, 62, 36, 179, 84, 10, 8, 168, 144, 169, 66, 83},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 142, 222, 157, 213, 110, 182, 24, 122, 107, 57, 185, 144, 211, 163, 120, 33},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 252, 18, 148, 68, 155, 1, 169, 179, 205, 164, 133, 86, 121, 70, 34, 236},
			padder:   pkcs7Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{141, 103, 78, 66, 218, 130, 83, 62, 203, 25, 178, 58, 13, 12, 22, 213},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmn"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{185, 120, 176, 119, 188, 33, 56, 139, 180, 61, 193, 193, 140, 156, 83, 117},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmno"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 129, 37, 158, 98, 203, 91, 236, 56, 191, 68, 48, 174, 5, 233, 147, 42},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnop"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 231, 85, 177, 1, 69, 253, 47, 38, 93, 178, 187, 133, 218, 155, 46, 111},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopq"),
		},
		{
			key:      []byte("0123456789abcdefghijklmnopqrstuv"),
			data:     []byte{130, 105, 207, 64, 216, 184, 142, 158, 220, 211, 235, 132, 78, 88, 51, 81, 155, 157, 107, 85, 209, 89, 135, 151, 183, 184, 162, 69, 249, 118, 33, 213},
			padder:   ansiX923Padding{},
			expected: []byte("abcdefghijklmnopqr"),
		},
	}
	// Test
	for i, c := range cases {
		m := NewECB(c.key)
		m.padder = c.padder
		ret, _ := m.Decrypt(c.data)
		if !bytes.Equal(ret, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, ret, c.expected)
		}
	}
}
