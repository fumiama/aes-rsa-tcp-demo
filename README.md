# C/S demo with RSA and AES Algorithm

This program is my homework for the IoT course, demonstrating the use of symmetric encryption AES and asymmetric encryption RSA.

## Communication Process
### Server
1. Create a socket and listen for TCP connections.
2. Upon receiving a connection, perform corresponding operations based on the client's request:
   - `utils.PacketTypeInit`: Encrypt its own RSA public key with the pre-shared AES key and send it to the client.
   - `utils.PacketTypeComm`: Decrypt and print the message sent by the client using `RSA-OAEP` with the private key, then encrypt its replyment with a **self-made** signature algorithm using the RSA private key and send it.
3. When the client actively disconnects, one processing ends.

### Client
1. Establish a TCP connection to the server address.
2. Send a `utils.PacketTypeInit` packet to the server to request the RSA key.
3. Continuously send `Hello` to the server using `EncryptOAEP` while decrypting and printing the message sent by server with its public key using the **self-made** signature algorithm.
4. When the user manually terminates, close the connection to the server.

## Packet Protocol

The overall encapsulation is defined in [utils/packet.go](utils/packet.go).
```
0        15   23
┌─────────┬────┬──────────────┐
│   len   │type│ ... data ... │
└─────────┴────┴──────────────┘
```

### len
The length of the packet without itself.
### type
Defined in [utils/packet.go](utils/packet.go).
```go
const (
	PacketTypeInit PacketType = iota // PacketTypeInit pass RSA pubkey by AES pre-shared key
	PacketTypeComm                   // PacketTypeComm normal communication
	PacketTypeTop                    // PacketTypeTop for valid checking
)
```
### data
The payload, whose type is described by the `type` field.
#### PacketTypeInit
Defined in [utils/packet_init.go](utils/packet_init.go).
```
0    7       23                87
┌────┬────────┬─────────────────┬──────────────────────┐
│type│ length │  pub key crc64  │     x509rsapubkey    │
└────┴────────┴─────────────────┴──────────────────────┘
```
- **type**: `PacketInitTypeReq` or `PacketInitTypeAck`
- **length**: length of `x509rsapubkey`
#### PacketTypeComm
The whole data field is encrypted by RSA and can fill in with any data, which is plain text in this demo.

## Interesting Points
### The Implementation of [Base16384](https://github.com/fumiama/base16384)
Base16384 is a base64-like algorithm designed by me. It can encode binary file to printable utf16be, and vice versa.

In this demo, the [RSA Private Key](rsa_2048_private_x509.b14) and AES key is saved and passed by base16384 format.
### The Usage of Raw RSA Encrypting Method
In the file [utils/rsa.go](utils/rsa.go), I use `go:linkname` to hook the private function of `crypto/rsa` library and realized a **self-made** signature algorithm that can get the decoding result but not just verify whether it is valid (unlike the official method `rsa.VerifyPKCS1v15`).
## Demo
See the video below.


https://github.com/fumiama/aes-rsa-tcp-demo/assets/41315874/e4f6522b-e147-4a2f-add3-3a2abb90e96b

