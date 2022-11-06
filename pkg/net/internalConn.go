package net

import (
	"github.com/cryptonetworking/cryptosig"
	"github.com/cryptonetworking/kex/pkg/handshake"
	"github.com/cryptonetworking/kex/utils"
	encryptedStream "github.com/nknorg/encrypted-stream"
	"net"
)

type internalConn struct {
	peerPublicKey *cryptosig.PublicKey
	conn          *encryptedStream.EncryptedStream
}

func (c *internalConn) RemotePublicKey() *cryptosig.PublicKey {
	return c.peerPublicKey
}

func (c *internalConn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c *internalConn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func newConn(c net.Conn, mySecretKey *cryptosig.SecretKey, client bool) (_ *internalConn, err error) {
	var key []byte
	var peerPK *cryptosig.PublicKey
	if client {
		key, peerPK, err = handshake.Client(c, mySecretKey)
		if err != nil {
			return nil, err
		}
	} else {
		key, peerPK, err = handshake.Server(c, mySecretKey)
		if err != nil {
			return nil, err
		}
	}
	ec := utils.Must(encryptedStream.NewEncryptedStream(c, &encryptedStream.Config{
		Cipher:                   utils.Must(encryptedStream.NewAESGCMCipher(key)),
		MaxChunkSize:             512,
		Initiator:                client,
		SequentialNonce:          true,
		DisableNonceVerification: false,
	}))
	return &internalConn{
		peerPublicKey: peerPK,
		conn:          ec,
	}, nil
}
