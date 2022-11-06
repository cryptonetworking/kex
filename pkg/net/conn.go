package net

import (
	"github.com/cryptonetworking/cryptosig"
	"github.com/cryptonetworking/kex/utils"
	"net"
	"time"
)

type Conn struct {
	conn        *utils.Lazy[*internalConn]
	raw         net.Conn
	mySecretKey *cryptosig.SecretKey
}

func (c *Conn) RemotePublicKey() *cryptosig.PublicKey {
	v, e := c.conn.Get()
	if e != nil {
		return nil
	}
	return v.RemotePublicKey()
}

func (c *Conn) Raw() net.Conn {
	return c.raw
}

func (c *Conn) LocalSecretKey() *cryptosig.SecretKey {
	return c.mySecretKey
}
func (c *Conn) Read(b []byte) (n int, err error) {
	v, e := c.conn.Get()
	if e != nil {
		return 0, e
	}
	return v.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	v, e := c.conn.Get()
	if e != nil {
		return 0, e
	}
	return v.Write(b)
}

func (c *Conn) Close() error {
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.raw.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.raw.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}
func (c *Conn) Handshake() error {
	_, e := c.conn.Get()
	return e
}

func NewConn(c net.Conn, mySecretKey *cryptosig.SecretKey) *Conn {
	return &Conn{utils.NewLazy(func() (*internalConn, error) {
		return newConn(c, mySecretKey, true)
	}), c, mySecretKey}
}
