package main

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"socket/utils"
	"time"

	base14 "github.com/fumiama/go-base16384"
)

func main() {
	server := flag.String("s", "0.0.0.0:12345", "server host:port")
	aespsh := flag.String("aes", "矲晊泞柯碍嘖另蚡蔼帀㴂", "the AES preshard key of base16384 format")
	flag.Parse()
	if *aespsh == "" {
		fmt.Println("must give parameter -aes")
		return
	}
	aescipher, err := aes.NewCipher(base14.DecodeFromString(*aespsh))
	if err != nil {
		fmt.Println("parse AES preshared key error:", err)
		return
	}
	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(*server)))
	if err != nil {
		fmt.Println("Connect to server error:", err)
		return
	}
	defer conn.Close()
	fmt.Println("Ronnected to server", conn.RemoteAddr())
	// request rsa pubkey
	packet := utils.Packet{}
	packet.Typ = utils.PacketTypeInit
	packet.Dat, err = utils.NewPacketInit(nil, nil)
	if err != nil {
		fmt.Println("Wrap init packet err:", err)
		return
	}
	data, err := packet.ToBytes()
	if err != nil {
		fmt.Println("Wrap packet err:", err)
		return
	}
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Write to server", conn.RemoteAddr(), "error:", err)
		return
	}
	packet, err = utils.ReadPacket(conn)
	if err != nil {
		fmt.Println("Read packet from server", conn.RemoteAddr(), "error:", err)
		return
	}
	if packet.Typ != utils.PacketTypeInit {
		fmt.Println("Unexpected packet type from server")
		return
	}
	x509rsapubkey, err := utils.ParsePacketInit(aescipher, packet.Dat)
	if err != nil {
		fmt.Println("Parse init packet error:", err)
		return
	}
	rsapubk, err := x509.ParsePKCS1PublicKey(x509rsapubkey)
	if err != nil {
		fmt.Println("Parse x509rsapubkey error:", err)
		return
	}
	fmt.Println("Get x509rsapubkey successfully")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	count := 0
	for range t.C {
		count++
		packet.Typ = utils.PacketTypeComm
		data, err = rsa.EncryptOAEP(
			md5.New(), rand.Reader, rsapubk,
			base14.StringToBytes(fmt.Sprintf("Hello! This is my No.%d communication.", count)),
			nil,
		)
		if err != nil {
			fmt.Println("EncryptOAEP err:", err)
			return
		}
		packet.Dat = data
		data, err := packet.ToBytes()
		if err != nil {
			fmt.Println("Wrap packet err:", err)
			return
		}
		_, err = conn.Write(data)
		if err != nil {
			fmt.Println("Write to server", conn.RemoteAddr(), "error:", err)
			return
		}
		packet, err = utils.ReadPacket(conn)
		if err != nil {
			fmt.Println("Read packet from server", conn.RemoteAddr(), "error:", err)
			return
		}
		if err != nil {
			fmt.Println("Receive from server", conn.RemoteAddr(), "error:", err)
			continue
		}
		data, err = utils.RSAPublicKeyDecrypt(rsapubk, packet.Dat)
		if err != nil {
			fmt.Println("RSAPublicKeyDecrypt from server", conn.RemoteAddr(), "error:", err)
			continue
		}
		fmt.Println("Receive from server", conn.RemoteAddr(), ":", base14.BytesToString(data))
	}
}
