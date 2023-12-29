package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestPacketInit(t *testing.T) {
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	aescipher, err := aes.NewCipher(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	rsak := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	data, err := NewPacketInit(aescipher, rsak)
	if err != nil {
		t.Fatal(err)
	}
	parsedk, err := ParsePacketInit(aescipher, data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rsak, parsedk) {
		t.Fatal("unexpected 1")
	}
	data, err = NewPacketInit(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedk, err = ParsePacketInit(aescipher, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedk) > 0 {
		t.Fatal("unexpected 2")
	}
}
