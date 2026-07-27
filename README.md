# Ann*Go

## Overview
Ann*Go is an encryption and decryption utility.  
Go has the crypto modules and this is an easy-to-use version of those modules.

## Install
    # go get github.com/tsukinoha/anngo

## Mode
|No|Mode|Function|
|-|-|-|
|1|CBC|NewAesCbc(key, iv []byte)|
|2|CFB|NewAesCfb(key, iv []byte)|
|3|OFB|NewAesOfb(key, iv []byte)|
|4|CTR|NewAesCtr(key, iv []byte)|

## Padding
|No|Padding|Function|Note|
|-|-|-|-|
|1|PKCS7|NewPkcs7()|This is a default padding.|
|2|ANSI X9.23|NewAnsiX923()|ANSI X9.23 padding.|
|3|ISO 10126|NewIso10126()|ISO 10126 padding.|
|4|Zero|NewZero()|Padding with 0x00. Not Recommended. There is no guarantee that it will return to normal.|

## Usage
```go
import (
    "github.com/tsukinoha/anngo"
    "fmt"
    "os"
)

func main() {
    iv := anngo.Generate(16) // Initial Vector
    key := anngo.Resize([]byte("Ann*Go/Example/Key"), 16)
    aes, err := NewAesCbc(key, iv)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }
    aes.Padding(NewAnsiX923())

    // Encrypt
    cipherText, err := aes.Encrypt([]byte("plain_text"))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }
    fmt.Println(cipherText)

    // Decrypt
    plainText, err := aes.Decrypt(cipherText)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s", err)
        os.Exit(1)
    }
    fmt.Println(plainText)
}
```

## License
Ann*Go is distributed under The MIT License.  
https://opensource.org/license/mit
