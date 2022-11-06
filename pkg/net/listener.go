package net

import (
	"github.com/cryptonetworking/cryptosig"
	"github.com/cryptonetworking/kex/utils"
	"net"
)

type Listener struct {
	secretKey *cryptosig.SecretKey
	ln        net.Listener
}

func (l *Listener) Accept() (net.Conn, error) {
	return l.AcceptKex()
}

func (l *Listener) AcceptKex() (*Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return newConnServer(conn, l.secretKey), nil
}

func (l *Listener) Close() error {
	return l.ln.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}
func (l *Listener) SecretKey() *cryptosig.SecretKey {
	return l.secretKey
}

func NewListener(ln net.Listener, secretKey *cryptosig.SecretKey) *Listener {
	return &Listener{ln: ln, secretKey: secretKey}
}

func newConnServer(c net.Conn, mySecretKey *cryptosig.SecretKey) *Conn {
	return &Conn{utils.NewLazy(func() (*internalConn, error) {
		return newConn(c, mySecretKey, false)
	}), c, mySecretKey}
}
