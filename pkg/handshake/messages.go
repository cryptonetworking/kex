package handshake

import (
	"github.com/cryptonetworking/cryptosig"
)

type req struct {
	ClientEphemeralPublicKey    [32]byte             `json:"epk"`
	ClientPublicKey             *cryptosig.PublicKey `json:"pk"`
	ClientEphemeralPublicKeySig *cryptosig.Signature `json:"sig"`
}

type rawRep struct {
	ServerPublicKey             *cryptosig.PublicKey `json:"pk"`
	ServerEphemeralPublicKeySig *cryptosig.Signature `json:"sig"`
}

type secRep struct {
	SecMsgNonce              [24]byte `json:"nonce"`
	ServerEphemeralPublicKey [32]byte `json:"epk"`
	SecMsg                   []byte   `json:"msg"` //rawRep
}
