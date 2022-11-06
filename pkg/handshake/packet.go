package handshake

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

var ErrTooLargePacket = errors.New("kex: too large packet")

func Recv(src io.Reader, max uint32) ([]byte, error) {
	var length [4]byte
	_, err := io.ReadFull(src, length[:])
	if err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(length[:])
	if l > max {
		return nil, ErrTooLargePacket
	}
	b := make([]byte, l)
	_, err = io.ReadFull(src, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func Send(dst io.Writer, b []byte) error {
	if len(b) >= math.MaxUint32 {
		return ErrTooLargePacket
	}
	buff := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buff[:4], uint32(len(b)))
	copy(buff[4:], b)
	_, err := dst.Write(buff)
	return err
}
