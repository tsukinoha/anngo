// PKCS#7
package anngo

import (
	"bytes"
)

func (p pkcs7Padding) Pad(str []byte) []byte {
	length := len(str)
	count := BlockSize - length%BlockSize
	padding := bytes.Repeat([]byte{byte(count)}, count)
	str = append(str, padding...)
	return str
}

func (p pkcs7Padding) Unpad(str []byte) []byte {
	length := len(str)
	if length < BlockSize {
		return str
	}
	last := str[length-1]
	if last < 0x01 || last > 0x10 {
		return str
	}
	suffix := bytes.Repeat([]byte{last}, int(last))
	idx := length - len(suffix)
	if !bytes.Equal(suffix, str[idx:]) {
		return str
	}

	return str[:idx]
}
