package kex

import (
	"bytes"
	"github.com/cryptonetworking/cryptosig"
	"github.com/cryptonetworking/cryptosig/pkg/ed25519"
	"github.com/cryptonetworking/kex/pkg/handshake"
	"github.com/cryptonetworking/kex/pkg/utils"
	"net"
	"sync"
	"testing"
)

func TestBehavior(t *testing.T) {
	s := cryptosig.GenerateSecretKey(ed25519.Algo)
	c := cryptosig.GenerateSecretKey(ed25519.Algo)
	ln := utils.Must(net.Listen("tcp", ":0"))
	t.Parallel()
	var wg sync.WaitGroup
	wg.Add(1)
	var k1, k2 []byte
	go func() {
		defer wg.Done()
		var err error
		var c2 *cryptosig.PublicKey
		conn := utils.Must(ln.Accept())
		defer conn.Close()
		k1, c2, err = handshake.Server(conn, s)
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(utils.Must(c2.MarshalText()), utils.Must(c.PublicKey().MarshalText())) {
			panic(handshake.ErrFailed)
		}
	}()
	var err error
	conn := utils.Must(net.Dial("tcp", ln.Addr().String()))
	defer conn.Close()
	k2, s2, err := handshake.Client(conn, c)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if !bytes.Equal(k1, k2) {
		t.Fatal()
	}
	if bytes.Equal(k1, make([]byte, len(k1))) {
		t.Fatal()
	}
	if !bytes.Equal(utils.Must(s2.MarshalText()), utils.Must(s.PublicKey().MarshalText())) {
		t.Fatal()
	}
}
