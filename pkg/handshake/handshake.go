package handshake

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/cryptonetworking/cryptosig"
	"github.com/cryptonetworking/kex/utils"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"net"
)

var MaxPacketSize uint32 = 1000

func Client(conn net.Conn, my *cryptosig.SecretKey) (key []byte, other *cryptosig.PublicKey, err error) {
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	if err := Send(conn, utils.Must(json.Marshal(&req{
		ClientEphemeralPublicKey:    *p,
		ClientPublicKey:             my.PublicKey(),
		ClientEphemeralPublicKeySig: my.Sign(p[:]),
	}))); err != nil {
		return nil, nil, err
	}
	b, err := Recv(conn, MaxPacketSize)
	if err != nil {
		return nil, nil, err
	}
	var rep secRep
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, nil, err
	}
	var k [32]byte
	box.Precompute(&k, &rep.ServerEphemeralPublicKey, s)
	msg, ok := secretbox.Open(nil, rep.SecMsg, &rep.SecMsgNonce, &k)
	if !ok {
		return nil, nil, ErrFailed
	}
	var raw rawRep
	if err = json.Unmarshal(msg, &raw); err != nil {
		return nil, nil, err
	}
	if err = raw.ServerPublicKey.Verify(raw.ServerEphemeralPublicKeySig, rep.ServerEphemeralPublicKey[:]); err != nil {
		return nil, nil, err
	}
	return k[:], raw.ServerPublicKey, nil
}

var ErrFailed = errors.New(": handshake failed")

func Server(conn net.Conn, my *cryptosig.SecretKey) (key []byte, other *cryptosig.PublicKey, err error) {
	b, err := Recv(conn, MaxPacketSize)
	if err != nil {
		return nil, nil, err
	}
	var req req
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, nil, err
	}
	if err = req.ClientPublicKey.Verify(req.ClientEphemeralPublicKeySig, req.ClientEphemeralPublicKey[:]); err != nil {
		return nil, nil, err
	}
	p, s, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	var k [32]byte
	box.Precompute(&k, &req.ClientEphemeralPublicKey, s)
	rawRep := rawRep{
		ServerPublicKey:             my.PublicKey(),
		ServerEphemeralPublicKeySig: my.Sign(p[:]),
	}
	if err = Send(conn, utils.Must(json.Marshal(&secRep{
		SecMsgNonce:              nonce,
		ServerEphemeralPublicKey: *p,
		SecMsg:                   secretbox.Seal(nil, utils.Must(json.Marshal(&rawRep)), &nonce, &k),
	}))); err != nil {
		return nil, nil, err
	}
	return k[:], req.ClientPublicKey, nil
}
