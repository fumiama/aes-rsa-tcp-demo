package utils

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"hash/crc64"
	"math"
	_ "unsafe"
)

//go:linkname encrypt crypto/rsa.encrypt
func encrypt(pub *rsa.PublicKey, plaintext []byte) ([]byte, error)

//go:linkname decrypt crypto/rsa.decrypt
func decrypt(priv *rsa.PrivateKey, ciphertext []byte, check bool) ([]byte, error)

// RSAPrivateKeyEncrypt use the method generally in sign
func RSAPrivateKeyEncrypt(priv *rsa.PrivateKey, plaintext []byte) ([]byte, error) {
	if len(plaintext) > math.MaxUint16 {
		return nil, errors.New("plaintext too large")
	}
	h := crc64.New(crc64.MakeTable(crc64.ECMA))
	_, err := h.Write(plaintext)
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(plaintext)+8+2)
	n := copy(data[:], plaintext)
	binary.LittleEndian.PutUint64(data[n:n+8], h.Sum64())
	binary.LittleEndian.PutUint16(data[n+8:n+8+2], uint16(len(plaintext)))
	return decrypt(priv, data, false)
}

// RSAPublicKeyDecrypt use the method generally in sign
func RSAPublicKeyDecrypt(pub *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	data, err := encrypt(pub, ciphertext)
	if err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint16(data[len(data)-2:])
	p := len(data) - int(n) - 8 - 2
	if p < 0 || p > len(data) {
		return nil, errors.New("invalid ciphertext length")
	}
	data = data[p:]
	h := crc64.New(crc64.MakeTable(crc64.ECMA))
	_, err = h.Write(data[:len(data)-8-2])
	if err != nil {
		return nil, err
	}
	if h.Sum64() != binary.LittleEndian.Uint64(data[len(data)-8-2:len(data)-2]) {
		return nil, errors.New("invalid ciphertext")
	}
	return data[:len(data)-8-2], nil
}
