package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSA(t *testing.T) {
	testtext := []byte("test RSAPrivateKeyEncrypt")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := RSAPrivateKeyEncrypt(priv, testtext)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := RSAPublicKeyDecrypt(&priv.PublicKey, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(testtext, dec) {
		t.Fatal("expected", string(testtext), "but got", string(dec))
	}
}
