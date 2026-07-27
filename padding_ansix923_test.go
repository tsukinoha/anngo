package anngo

import (
	"bytes"
	"testing"
)

func TestAnsiX923Pad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        []byte{},
			expected: append(bytes.Repeat([]byte{0x00}, 15), []byte{0x10}...),
		},
		{
			s:        []byte("0123456789abcdef"),
			expected: append([]byte("0123456789abcdef"), append(bytes.Repeat([]byte{0x00}, 15), []byte{0x10}...)...),
		},
		{
			s:        []byte("0123456789abcdefg"),
			expected: append(append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 14)...), []byte{0x0f}...),
		},
		{
			s:        []byte("0123456789abcdefgh"),
			expected: append(append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 13)...), []byte{0x0e}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrst"),
			expected: append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x02}...),
		},
		{
			s:        []byte("0123456789abcdefghijklmnopqrstu"),
			expected: append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
		},
	}
	p := ansiX923Padding{}
	for i, c := range cases {
		r := p.Pad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Pad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestAnsiX923Unpad(t *testing.T) {
	cases := []struct {
		s        []byte
		expected []byte
	}{
		{
			s:        []byte{},
			expected: []byte{},
		},
		{
			s:        []byte("0123456789"),
			expected: []byte("0123456789"),
		},
		{
			s:        append(append([]byte("0123456789abcdef"), bytes.Repeat([]byte{0x00}, 15)...), []byte{0x10}...),
			expected: []byte("0123456789abcdef"),
		},
		{
			s:        append(append([]byte("0123456789abcdefg"), bytes.Repeat([]byte{0x00}, 14)...), []byte{0x0f}...),
			expected: []byte("0123456789abcdefg"),
		},
		{
			s:        append(append([]byte("0123456789abcdefgh"), bytes.Repeat([]byte{0x00}, 13)...), []byte{0x0e}...),
			expected: []byte("0123456789abcdefgh"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrst"), []byte{0x00, 0x02}...),
			expected: []byte("0123456789abcdefghijklmnopqrst"),
		},
		{
			s:        append([]byte("0123456789abcdefghijklmnopqrstu"), []byte{0x01}...),
			expected: []byte("0123456789abcdefghijklmnopqrstu"),
		},
	}
	p := ansiX923Padding{}
	for i, c := range cases {
		r := p.Unpad(c.s)
		if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}
