package utils

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

type PacketType uint8

const (
	PacketTypeInit PacketType = iota // PacketTypeInit pass RSA pubkey by AES pre-shared key
	PacketTypeComm                   // PacketTypeComm normal communication
	PacketTypeTop                    // PacketTypeTop for valid checking
)

// Packet is the communicating proxy
type Packet struct {
	Len uint16     // Len packet length LE
	Typ PacketType // Typ packet type
	Dat []byte     // Dat payload
}

// ParsePacket from bytes
func ParsePacket(d []byte) (p Packet, err error) {
	l := binary.LittleEndian.Uint16(d[:2])
	if 2+int(l) != len(d) {
		err = errors.New("invalid packet len")
		return
	}
	p.Len = l
	p.Typ = PacketType(d[2])
	p.Dat = d[3:]
	return
}

// ReadPacket from io.Reader
func ReadPacket(r io.Reader) (p Packet, err error) {
	var buf [2]byte
	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return
	}
	l := binary.LittleEndian.Uint16(buf[:])
	data := make([]byte, l)
	_, err = io.ReadFull(r, data)
	if err != nil {
		return
	}
	p.Len = l
	p.Typ = PacketType(data[0])
	p.Dat = data[1:]
	return
}

// ToBytes marshal packet into bytes
func (p *Packet) ToBytes() ([]byte, error) {
	l := 1 + len(p.Dat)
	if l > math.MaxUint16 {
		return nil, errors.New("packet data too large")
	}
	if p.Typ >= PacketTypeTop {
		return nil, errors.New("invalid packet tpye")
	}
	p.Len = uint16(l)
	return p.MustToBytes(), nil
}

// MustToBytes don't do any check
func (p *Packet) MustToBytes() []byte {
	data := make([]byte, 2+1+len(p.Dat))
	binary.LittleEndian.PutUint16(data[:2], p.Len)
	data[2] = byte(p.Typ)
	copy(data[3:], p.Dat)
	return data
}
