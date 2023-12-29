package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestAES(t *testing.T) {
	var buf [32]byte
	var data [123]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = rand.Read(data[:])
	if err != nil {
		t.Fatal(err)
	}
	aescipher, err := aes.NewCipher(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	encdat := EncryptAES(aescipher, data[:])
	decdat := DecryptAES(aescipher, encdat)[:123]
	if !bytes.Equal(data[:], decdat) {
		t.Fatal("expected " + hex.EncodeToString(data[:]) + " but got " + hex.EncodeToString(decdat))
	}
}

func TestAESInplace(t *testing.T) {
	var buf [32]byte
	var data [128]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = rand.Read(data[:])
	if err != nil {
		t.Fatal(err)
	}
	aescipher, err := aes.NewCipher(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	org := data
	err = EncryptAESInplace(aescipher, data[:])
	if err != nil {
		t.Fatal(err)
	}
	err = DecryptAESInplace(aescipher, data[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:], org[:]) {
		t.Fatal("expected " + hex.EncodeToString(org[:]) + " but got " + hex.EncodeToString(data[:]))
	}
}
