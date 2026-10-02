# Ann*Go

## Overview
Ann*Go is an AES encryption and decryption utility.  
Go has the crypto modules and this is an easy-to-use version of those modules.

## Install
    $ go get github.com/tsukinoha/anngo

## Key
The key size selects the AES variant.

|Constant|Key size|Cipher|
|-|-|-|
|`AES128`|16 bytes|AES-128|
|`AES192`|24 bytes|AES-192|
|`AES256`|32 bytes|AES-256|

An invalid key size is reported as an error by `Encrypt` / `Decrypt`.

## Mode
|No|Mode|Function|IV|Padding|
|-|-|-|-|-|
|1|CBC|`NewCBC(key []byte) *CBC`|Yes|Yes|
|2|CFB|`NewCFB(key []byte) *CFB`|Yes|No|
|3|CTR|`NewCTR(key []byte) *CTR`|Yes|No|
|4|ECB|`NewECB(key []byte) *ECB`|No|Yes|
|5|OFB|`NewOFB(key []byte) *OFB`|Yes|No|

Every mode implements `ModeInterface`.

```go
type ModeInterface interface {
    Encrypt([]byte) ([]byte, error)
    Decrypt([]byte) ([]byte, error)
}
```

ECB encrypts identical blocks to identical ciphertext and is not recommended.

### IV
Modes that use an IV generate a random 16-byte IV in the constructor.

|Method|Description|
|-|-|
|`IV() []byte`|Returns a copy of the current IV. Store it with the ciphertext; it is needed for decryption.|
|`SetIV(iv []byte) error`|Sets the IV. It must be exactly `BlockSize` (16) bytes.|

`GenerateIV(size int) ([]byte, error)` returns `size` random bytes.

Never reuse the same key and IV pair for different messages.

## Padding
Padding applies to CBC and ECB only. CFB, CTR and OFB are stream modes and the ciphertext has the same length as the plaintext.

|No|Padding|Method|Note|
|-|-|-|-|
|1|PKCS7|`Pkcs7()`|This is the default padding.|
|2|ANSI X9.23|`AnsiX923()`|Padding with 0x00 and the length in the last byte.|

## Errors
|Error|Returned when|
|-|-|
|`ErrInvalidCiphertextSize`|CBC / ECB ciphertext is empty or not a multiple of the block size.|
|`ErrInvalidPadding`|CBC / ECB padding is broken after decryption (e.g. wrong key, wrong IV, wrong padding scheme or tampered ciphertext).|
|`ErrAuthentication`|CBC / ECB with HMAC enabled: the tag does not match (tampered, truncated or wrong MAC key / IV).|
|`ErrInvalidMACKey`|`HMAC()` was given a key shorter than `MinMACKeySize` (16) bytes.|

## Authentication (HMAC)
Without authentication, tampering is not detected. For CBC, returning `ErrInvalidPadding` can also be abused as a padding oracle to recover the plaintext.
When the ciphertext comes from an untrusted source, enable Encrypt-then-MAC on CBC / ECB.

|Method|Description|
|-|-|
|`HMAC(key []byte) error`|Enables HMAC-SHA256. The key must be at least `MinMACKeySize` (16) bytes.|

- `Encrypt` returns `ciphertext || tag`, where the tag is `HMAC-SHA256(key, IV || ciphertext)` and is `MACSize` (32) bytes long. ECB has no IV, so its tag covers the ciphertext only.
- `Decrypt` verifies the tag in constant time before removing the padding. Any modification is reported as `ErrAuthentication`, so no padding oracle is exposed.
- Use a MAC key that is independent of the encryption key, and the same MAC key on both sides.

CFB, CTR and OFB have no HMAC option. They do not use padding, but they also do not detect tampering.

## Concurrency
An instance can be shared by multiple goroutines for `Encrypt` / `Decrypt`.
Call the configuration methods (`SetIV`, `Pkcs7`, `AnsiX923`, `HMAC`) before sharing it.

## Usage
```go
package main

import (
    "fmt"
    "os"

    "github.com/tsukinoha/anngo"
)

func main() {
    key := []byte("Ann*Go/Example/Key/0123456789abc") // 32 bytes: AES-256
    macKey := []byte("Ann*Go/Example/MAC/Key/0123456789") // independent of key

    // Encrypt
    enc := anngo.NewCBC(key)
    enc.AnsiX923()
    if err := enc.HMAC(macKey); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s\n", err)
        os.Exit(1)
    }
    iv := enc.IV()
    cipherText, err := enc.Encrypt([]byte("plain_text"))
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s\n", err)
        os.Exit(1)
    }
    fmt.Println(cipherText)

    // Decrypt
    dec := anngo.NewCBC(key)
    dec.AnsiX923()
    if err := dec.HMAC(macKey); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s\n", err)
        os.Exit(1)
    }
    if err := dec.SetIV(iv); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s\n", err)
        os.Exit(1)
    }
    plainText, err := dec.Decrypt(cipherText)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %s\n", err)
        os.Exit(1)
    }
    fmt.Println(string(plainText))
}
```

## License
Ann*Go is distributed under The MIT License.  
https://opensource.org/license/mit
