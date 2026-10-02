// PKCS#7
package anngo

import (
	"bytes"
	"crypto/subtle"
)

func (p pkcs7Padding) Pad(str []byte) []byte {
	length := len(str)
	count := BlockSize - length%BlockSize
	dst := make([]byte, length+count)
	copy(dst, str)
	copy(dst[length:], bytes.Repeat([]byte{byte(count)}, count))
	return dst
}

// Unpad checks the padding in constant time with respect to its content.
func (p pkcs7Padding) Unpad(str []byte) ([]byte, error) {
	length := len(str)
	if length == 0 || length%BlockSize != 0 {
		return nil, ErrInvalidPadding
	}
	last := str[length-1]
	count := int(last)
	good := subtle.ConstantTimeLessOrEq(1, count) & subtle.ConstantTimeLessOrEq(count, BlockSize)
	for i := 1; i <= BlockSize; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i, count)
		eq := subtle.ConstantTimeByteEq(str[length-i], last)
		good &= subtle.ConstantTimeSelect(inPad, eq, 1)
	}
	if good != 1 {
		return nil, ErrInvalidPadding
	}
	return str[:length-count], nil
}
