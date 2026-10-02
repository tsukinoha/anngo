// ANSI X9.23
package anngo

import (
	"crypto/subtle"
)

func (p ansiX923Padding) Pad(str []byte) []byte {
	length := len(str)
	count := BlockSize - length%BlockSize
	// make() zero-fills, so only the last byte needs to be set.
	dst := make([]byte, length+count)
	copy(dst, str)
	dst[len(dst)-1] = byte(count)
	return dst
}

// Unpad checks the padding in constant time with respect to its content.
func (p ansiX923Padding) Unpad(str []byte) ([]byte, error) {
	length := len(str)
	if length == 0 || length%BlockSize != 0 {
		return nil, ErrInvalidPadding
	}
	count := int(str[length-1])
	good := subtle.ConstantTimeLessOrEq(1, count) & subtle.ConstantTimeLessOrEq(count, BlockSize)
	for i := 2; i <= BlockSize; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i, count)
		eq := subtle.ConstantTimeByteEq(str[length-i], 0x00)
		good &= subtle.ConstantTimeSelect(inPad, eq, 1)
	}
	if good != 1 {
		return nil, ErrInvalidPadding
	}
	return str[:length-count], nil
}
