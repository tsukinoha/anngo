// ANSI X9.23
package anngo

import (
	"bytes"
)

func (p ansiX923Padding) Pad(str []byte) []byte {
	length := len(str)
	count := BlockSize - length%BlockSize
	padding := append(bytes.Repeat([]byte{0x00}, count-1), byte(count))
	str = append(str, padding...)
	return str
}

func (p ansiX923Padding) Unpad(str []byte) []byte {
	length := len(str)
	if length < BlockSize {
		return str
	}
	last := str[length-1]
	if last < 0x01 || last > 0x10 {
		return str
	}
	suffix := append(bytes.Repeat([]byte{0x00}, int(last)-1), last)
	idx := length - len(suffix)
	if !bytes.Equal(suffix, str[idx:]) {
		return str
	}
	return str[:idx]
}
