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
		r, err := p.Unpad(c.s)
		if err != nil {
			t.Errorf("[%d] Unpad\n  Error   : %v", i, err)
		} else if !bytes.Equal(r, c.expected) {
			t.Errorf("[%d] Unpad\n  Result  : %v\n  Expected: %v", i, r, c.expected)
		}
	}
}

func TestPkcs7UnpadInvalid(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("0123456789"),
		append([]byte("0123456789abcde"), 0x00),
		append([]byte("0123456789abcde"), 0x11),
		append([]byte("0123456789abcde"), 0xff),
		append([]byte("0123456789abc"), 0x02, 0x03, 0x03),
		append(bytes.Repeat([]byte{0x00}, 15), 0x10),
		append([]byte("0123456789abcdefg"), 0x02, 0x02),
	}
	p := pkcs7Padding{}
	for i, c := range cases {
		r, err := p.Unpad(c)
		if err != ErrInvalidPadding {
			t.Errorf("[%d] Unpad\n  Result  : %v, %v\n  Expected: %v", i, r, err, ErrInvalidPadding)
		}
	}
}

func TestPkcs7PadRoundTrip(t *testing.T) {
	p := pkcs7Padding{}
	for n := 0; n <= BlockSize*3; n++ {
		s := bytes.Repeat([]byte{0xab}, n)
		padded := p.Pad(s)
		if len(padded)%BlockSize != 0 || len(padded) <= n || len(padded)-n > BlockSize {
			t.Errorf("[%d] Pad length: %d", n, len(padded))
			continue
		}
		r, err := p.Unpad(padded)
		if err != nil || !bytes.Equal(r, s) {
			t.Errorf("[%d] Unpad\n  Result  : %v, %v\n  Expected: %v", n, r, err, s)
		}
	}
}

func TestPkcs7PadDoesNotModifySource(t *testing.T) {
	buf := []byte("0123456789abcdefghijklmnopqrstuv")
	orig := bytes.Clone(buf)
	p := pkcs7Padding{}
	p.Pad(buf[:10])
	if !bytes.Equal(buf, orig) {
		t.Errorf("source modified\n  Result  : %v\n  Expected: %v", buf, orig)
	}
}

// The constant-time Unpad must agree with a straightforward implementation
// for every last-byte value and every single-byte corruption of the block.
func TestPkcs7UnpadMatchesReference(t *testing.T) {
	ref := func(s []byte) ([]byte, bool) {
		n := int(s[len(s)-1])
		if n < 1 || n > BlockSize || !bytes.Equal(s[len(s)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
			return nil, false
		}
		return s[:len(s)-n], true
	}
	p := pkcs7Padding{}
	for last := 0; last < 256; last++ {
		for pos := -1; pos < BlockSize-1; pos++ {
			s := append([]byte("0123456789abcdef"), bytes.Repeat([]byte{byte(last)}, BlockSize)...)
			if pos >= 0 {
				s[BlockSize+pos] ^= 0x01
			}
			expected, ok := ref(s)
			r, err := p.Unpad(s)
			if ok != (err == nil) || !bytes.Equal(r, expected) {
				t.Errorf("last %#x pos %d\n  Result  : %v, %v\n  Expected: %v, %v", last, pos, r, err, expected, ok)
			}
		}
	}
}
