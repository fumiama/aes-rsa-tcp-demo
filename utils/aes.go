package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// NewAESPresharedKey typ AES-128, AES-192, or AES-256.
func NewAESPresharedKey(typ string) ([]byte, error) {
	sz := 0
	switch typ {
	case "AES-128":
		sz = 16
	case "AES-192":
		sz = 24
	case "AES-256":
		sz = 32
	}
	if sz <= 0 {
		return nil, aes.KeySizeError(sz)
	}
	k := make([]byte, sz)
	_, err := rand.Read(k)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// EncryptAES ...
func EncryptAES(aescipher cipher.Block, data []byte) []byte {
	blksz := aescipher.BlockSize()
	total := len(data)
	n := total / blksz
	if total%blksz > 0 {
		n++
	}
	encdat := make([]byte, blksz*n)
	copy(encdat, data)
	for i := 0; i < n; i++ {
		a := i * blksz
		b := (i + 1) * blksz
		aescipher.Encrypt(encdat[a:b], encdat[a:b])
	}
	return encdat
}

// EncryptAESInplace ...
func EncryptAESInplace(aescipher cipher.Block, data []byte) error {
	blksz := aescipher.BlockSize()
	total := len(data)
	n := total / blksz
	if total%blksz > 0 {
		n++
	}
	if len(data) < blksz*n {
		return errors.New("data is too short")
	}
	for i := 0; i < n; i++ {
		a := i * blksz
		b := (i + 1) * blksz
		aescipher.Encrypt(data[a:b], data[a:b])
	}
	return nil
}

// DecryptAES ...
func DecryptAES(aescipher cipher.Block, data []byte) []byte {
	blksz := aescipher.BlockSize()
	total := len(data)
	n := total / blksz
	decdat := make([]byte, blksz*n)
	for i := 0; i < n; i++ {
		a := i * blksz
		b := (i + 1) * blksz
		aescipher.Decrypt(decdat[a:b], data[a:b])
	}
	return decdat
}

// DecryptAESInplace ...
func DecryptAESInplace(aescipher cipher.Block, data []byte) error {
	blksz := aescipher.BlockSize()
	total := len(data)
	n := total / blksz
	for i := 0; i < n; i++ {
		a := i * blksz
		b := (i + 1) * blksz
		aescipher.Decrypt(data[a:b], data[a:b])
	}
	return nil
}
