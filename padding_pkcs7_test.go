package anngo

import (
	"bytes"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        []byte{},
			expected: bytes.Repeat([]byte{0x10}, 16),
		},
		{
			s:        []byte("0123456789abcdef"),
			expected: append([]byte("0123456789abcdef"), bytes.Repeat([]byte{0x10}, 16)...),
		},
		{
			s:        []byte("0123456789abcdefg"),
			expected: append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x0f}, 15)...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x0e}, 14)...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x02, 0x02}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
		},
	}
	p := pkcs7Padding{}
	for i, c := range cases {
		r := p.Pad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Pad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestPkcs7Unpad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        bytes.Repeat([]byte{0x10}, 16),
			expected: []byte{},
		},
		{
			s:        append([]byte("0123456789abcdef"), bytes.Repeat([]byte{0x10}, 16)...),
			expected: []byte("0123456789abcdef"),
		},
		{
			s:        append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x0f}, 15)...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x0e}, 14)...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append([]byte("0123456789abcdefghi"), bytes.Repeat([]byte{0x0d}, 13)...),
			expected: []byte("0123456789abcdefghi"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x02, 0x02}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := pkcs7Padding{}
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}
