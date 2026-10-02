package anngo

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateIV(t *testing.T) {
	cases := []struct {
		size     int
		expected int
	}{
		{size: 0, expected: 0},
		{size: 16, expected: 16},
		{size: 32, expected: 32},
	}
	for i, c := range cases {
		iv, err := GenerateIV(c.size)
		if err != nil {
			t.Errorf("\n<Case%d>\nError: %v\n", i, err)
		}
		length := len(iv)
		if length != c.expected {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, length, c.expected)
		}

	}
}

func TestCopyIV(t *testing.T) {
	b := make([]byte, 128)
	rand.Read(b)
	cases := []struct {
		d        []byte
		s        []byte
		expected []byte
	}{
		{d: make([]byte, 16), s: b[:16], expected: b[:16]},
	}
	for i, c := range cases {
		if err := copyIV(c.d, c.s); err != nil {
			t.Errorf("\n<Case%d>\nError: %v\n", i, err)
		}
		if !bytes.Equal(c.d, c.expected) {
			t.Errorf("\n<Case%d>\nResult:   %v\nExpected: %v\n", i, c.d, c.expected)
		}
	}
}

func TestCopyIVInvalid(t *testing.T) {
	cases := []struct {
		d []byte
		s []byte
	}{
		{d: make([]byte, 16), s: nil},
		{d: make([]byte, 16), s: make([]byte, 15)},
		{d: make([]byte, 16), s: make([]byte, 17)},
		{d: make([]byte, 8), s: make([]byte, 16)},
	}
	for i, c := range cases {
		if err := copyIV(c.d, c.s); err == nil {
			t.Errorf("\n<Case%d>\nExpected error\n", i)
		}
	}
}
