package utils

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc64"
)

type PacketInitType uint8

const (
	PacketInitTypeReq PacketInitType = iota // PacketInitTypeReq request RSA pubkey (by client)
	PacketInitTypeAck                       // PacketInitTypeAck give the key
	PacketInitTypeTop
)

// NewPacketInit x509rsapubkey = nil for req
func NewPacketInit(aescipher cipher.Block, x509rsapubkey []byte) ([]byte, error) {
	if len(x509rsapubkey) == 0 {
		return []byte{byte(PacketInitTypeReq)}, nil
	}
	blksz := aescipher.BlockSize()
	total := 2 + len(x509rsapubkey) + 8
	n := total / blksz
	if total%blksz > 0 {
		n++
	}
	data := make([]byte, 1+blksz*n)
	data[0] = byte(PacketInitTypeAck)
	encdat := data[1:]
	binary.LittleEndian.PutUint16(encdat[:2], uint16(len(x509rsapubkey)))
	h := crc64.New(crc64.MakeTable(crc64.ECMA))
	_, err := h.Write(x509rsapubkey)
	if err != nil {
		return nil, err
	}
	_ = h.Sum(encdat[2 : 2 : 2+8])
	copy(encdat[2+8:], x509rsapubkey)
	err = EncryptAESInplace(aescipher, encdat)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ParsePacketInit parse a init packet
func ParsePacketInit(aescipher cipher.Block, d []byte) (x509rsapubkey []byte, err error) {
	if len(d) == 0 {
		err = errors.New("invalid init packet length")
		return
	}
	if d[0] >= byte(PacketInitTypeTop) {
		err = errors.New("invalid init packet type")
		return
	}
	if d[0] == byte(PacketInitTypeReq) {
		return
	}
	data := DecryptAES(aescipher, d[1:])
	klen := binary.LittleEndian.Uint16(data[:2])
	if int(klen) > len(data[10:]) {
		err = errors.New("invalid init packet data length")
		return
	}
	x509rsapubkey = data[10 : 10+klen]
	h := crc64.New(crc64.MakeTable(crc64.ECMA))
	_, err = h.Write(x509rsapubkey)
	if err != nil {
		return nil, err
	}
	var buf [8]byte
	if !bytes.Equal(data[2:2+8], h.Sum(buf[:0])) {
		err = errors.New("invalid init packet data")
		return
	}
	return
}
