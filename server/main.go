package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/fumiama/aes-rsa-tcp-demo/utils"

	base14 "github.com/fumiama/go-base16384"
)

var countnum = uintptr(0)

func main() {
	listen := flag.String("l", "0.0.0.0:12345", "listening host:port")
	genaespsh := flag.String("gaes", "", "generate a new AES preshard key (AES-128, AES-192, or AES-256)")
	genrsakey := flag.Uint("grsa", 0, "generate a new RSA key pair of bits and save it to rsa_bits_private_x509.b14")
	rsapkfile := flag.String("rsaf", "rsa_2048_private_x509.b14", "specify the path of the RSA private key")
	aespsh := flag.String("aes", "矲晊泞柯碍嘖另蚡蔼帀㴂", "the AES preshard key of base16384 format")
	flag.Parse()
	if *genaespsh != "" {
		k, err := utils.NewAESPresharedKey(*genaespsh)
		if err != nil {
			fmt.Println("Generate new AES preshard key error:", err)
			return
		}
		fmt.Println("The generated AES preshared key is:", base14.EncodeToString(k))
		return
	}
	if *genrsakey != 0 {
		k, err := rsa.GenerateKey(rand.Reader, int(*genrsakey))
		if err != nil {
			fmt.Println("Generate new RSA key pair error:", err)
			return
		}
		f, err := os.Create(fmt.Sprintf("rsa_%d_private_x509.b14", *genrsakey))
		if err != nil {
			fmt.Println("Create new RSA private key error:", err)
			return
		}
		defer f.Close()
		_, err = f.WriteString(base14.EncodeToString(x509.MarshalPKCS1PrivateKey(k)))
		if err != nil {
			fmt.Println("Save new RSA private key error:", err)
			return
		}
		fmt.Println("The generated RSA key pair is:")
		fmt.Println("Private key: saved into", f.Name())
		fmt.Println("Public key:", base14.EncodeToString(x509.MarshalPKCS1PublicKey(&k.PublicKey)))
		return
	}
	rsapkeydata, err := os.ReadFile(*rsapkfile)
	if err != nil {
		fmt.Println("Read RSA private key error:", err)
		return
	}
	rsaprivkey, err := x509.ParsePKCS1PrivateKey(base14.DecodeFromString(base14.BytesToString(rsapkeydata)))
	if err != nil {
		fmt.Println("X509 parse RSA private key error:", err)
		return
	}
	x509rsapubkey := x509.MarshalPKCS1PublicKey(&rsaprivkey.PublicKey)
	if *aespsh == "" {
		fmt.Println("must give parameter -aes")
		return
	}
	aescipher, err := aes.NewCipher(base14.DecodeFromString(*aespsh))
	if err != nil {
		fmt.Println("parse AES preshared key error:", err)
		return
	}

	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.MustParseAddrPort(*listen)))
	if err != nil {
		fmt.Println("ListenTCP error:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Server bind and listen on", listener.Addr())

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("Accept error:", err)
			break
		}
		fmt.Println("Server accept connection from", conn.RemoteAddr())
		go handleclient(conn, aescipher, x509rsapubkey, rsaprivkey)
	}
}

func handleclient(conn *net.TCPConn, aescipher cipher.Block, x509rsapubkey []byte, rsaprivkey *rsa.PrivateKey) {
	var packet utils.Packet
	var err error
	defer conn.Close()
	for {
		packet, err = utils.ReadPacket(conn)
		if err == io.EOF {
			fmt.Println("Client", conn.RemoteAddr(), "closed connection")
			return
		}
		if err != nil {
			fmt.Println("Read packet from client", conn.RemoteAddr(), "error:", err)
			return
		}
		switch packet.Typ {
		case utils.PacketTypeInit:
			rsakeydata, err := utils.ParsePacketInit(aescipher, packet.Dat)
			if err != nil {
				fmt.Println("Parse init packet from client", conn.RemoteAddr(), "error:", err)
				return
			}
			if len(rsakeydata) > 0 { // unexpected situation
				return
			}
			// send RSA public key by AES encryption
			packet.Typ = utils.PacketTypeInit
			packet.Dat, err = utils.NewPacketInit(aescipher, x509rsapubkey)
			if err != nil {
				fmt.Println("Wrap RSA public key init packet to client", conn.RemoteAddr(), "error:", err)
				return
			}
			data, err := packet.ToBytes()
			if err != nil {
				fmt.Println("Wrap packet to client", conn.RemoteAddr(), "error:", err)
				return
			}
			_, err = conn.Write(data)
			if err != nil {
				fmt.Println("Send RSA public key to client", conn.RemoteAddr(), "error:", err)
				return
			}
			continue
		case utils.PacketTypeComm:
			data, err := rsa.DecryptOAEP(md5.New(), rand.Reader, rsaprivkey, packet.Dat, nil)
			if err != nil {
				fmt.Println("DecryptOAEP from client", conn.RemoteAddr(), "error:", err)
				return
			}
			fmt.Println("Recv data from client", conn.RemoteAddr(), ":", base14.BytesToString(data))
			packet.Typ = utils.PacketTypeComm
			data, err = utils.RSAPrivateKeyEncrypt(
				rsaprivkey, base14.StringToBytes(
					"Thank you for connecting! The data is "+
						strconv.Itoa(int(atomic.AddUintptr(&countnum, 1))),
				),
			)
			if err != nil {
				fmt.Println("RSAPrivateKeyEncrypt to client", conn.RemoteAddr(), "error:", err)
				return
			}
			packet.Dat = data
			data, err = packet.ToBytes()
			if err != nil {
				fmt.Println("Wrap packet to client", conn.RemoteAddr(), "error:", err)
				continue
			}
			_, err = conn.Write(data)
			if err != nil {
				fmt.Println("Send to client", conn.RemoteAddr(), "error:", err)
				continue
			}
			continue
		default:
			fmt.Println("Recv unknown packet type from client")
			return
		}
	}
}
