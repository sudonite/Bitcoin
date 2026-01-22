package networking

import (
	"crypto/rand"
	"math/big"
	"time"

	tx "github.com/sudonite/bitcoin/transaction"
)

// VersionMessage represents the Bitcoin "version" message used in the handshake.
type VersionMessage struct {
	command          string
	version          *big.Int
	services         *big.Int
	timestamp        *big.Int
	receiverServices *big.Int
	receiverIP       []byte
	receiverPort     uint16
	senderServices   *big.Int
	senderIP         []byte
	senderPort       uint16
	nonce            []byte
	userAgent        string
	latestBlock      *big.Int
	relay            bool
}

// VersionMessage represents the Bitcoin "version" message used in the handshake.
func NewVersionMessage() *VersionMessage {
	nonceBuf := make([]byte, 8)
	rand.Read(nonceBuf)
	return &VersionMessage{
		command:          "version",
		version:          big.NewInt(70015),
		services:         big.NewInt(0),
		timestamp:        big.NewInt(time.Now().Unix()),
		receiverServices: big.NewInt(0),
		receiverIP:       []byte{0x00, 0x00, 0x00, 0x00},
		receiverPort:     8333,
		senderServices:   big.NewInt(0),
		senderIP:         []byte{0x00, 0x00, 0x00, 0x00},
		senderPort:       8333,
		nonce:            nonceBuf,
		userAgent:        "goloand_bitcoin_lib",
		latestBlock:      big.NewInt(0),
		relay:            false,
	}
}

// Command returns the protocol command name for the version message.
func (v *VersionMessage) Command() string {
	return v.command
}

// Serialize converts the VersionMessage into a byte slice according to Bitcoin protocol.
func (v *VersionMessage) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result, tx.BigIntToLittleEndian(v.version, tx.LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, tx.BigIntToLittleEndian(v.services, tx.LITTLE_ENDIAN_8_BYTES)...)
	result = append(result, tx.BigIntToLittleEndian(v.timestamp, tx.LITTLE_ENDIAN_8_BYTES)...)
	result = append(result, tx.BigIntToLittleEndian(v.receiverServices, tx.LITTLE_ENDIAN_8_BYTES)...)
	//ip need to be 16 bytes with 0x00...ffff as prefix
	ipBuf := make([]byte, 16)
	for i := 0; i < 12; i++ {
		if i < 10 {
			ipBuf = append(ipBuf, 0x00)
		} else {
			ipBuf = append(ipBuf, 0xff)
		}
	}
	ipBuf = append(ipBuf, v.receiverIP...)
	result = append(result, ipBuf...)

	result = append(result, big.NewInt(int64(v.receiverPort)).Bytes()...)
	result = append(result, tx.BigIntToLittleEndian(v.senderServices, tx.LITTLE_ENDIAN_8_BYTES)...)
	ipBuf = make([]byte, 16)
	for i := 0; i < 12; i++ {
		if i < 10 {
			ipBuf = append(ipBuf, 0x00)
		} else {
			ipBuf = append(ipBuf, 0xff)
		}
	}
	ipBuf = append(ipBuf, v.senderIP...)
	result = append(result, ipBuf...)
	result = append(result, big.NewInt(int64(v.senderPort)).Bytes()...)

	result = append(result, v.nonce...)
	agentLen := tx.EncodeVarint(big.NewInt(int64(len(v.userAgent))))
	result = append(result, agentLen...)
	result = append(result, []byte(v.userAgent)...)
	result = append(result, tx.BigIntToLittleEndian(v.latestBlock, tx.LITTLE_ENDIAN_4_BYTES)...)
	if v.relay {
		result = append(result, 0x01)
	} else {
		result = append(result, 0x00)
	}

	return result

}

// VerAckMessage represents the Bitcoin "verack" message.
type VerAckMessage struct {
	command string
}

// NewVerAckMessage constructs a new VerAckMessage.
func NewVerAckMessage() *VerAckMessage {
	return &VerAckMessage{
		command: "verack",
	}
}

// Command returns the protocol command name for verack.
func (v *VerAckMessage) Command() string {
	return v.command
}

// Serialize returns an empty byte slice because "verack" has no payload.
func (v *VerAckMessage) Serialize() []byte {
	return []byte{}
}
