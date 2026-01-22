package networking

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
	tx "github.com/sudonite/bitcoin/transaction"
)

// NetworkEnvelope represents a Bitcoin network message envelope
type NetworkEnvelope struct {
	command []byte
	payload []byte
	testnet bool
	magic   []byte
}

// NewNetworkEnvelope creates a new network envelope for the given command and payload.
func NewNetworkEnvelope(command []byte, payload []byte, testnet bool) *NetworkEnvelope {
	network := &NetworkEnvelope{
		command: command,
		payload: payload,
		testnet: testnet,
	}

	if testnet {
		network.magic = []byte{0x0b, 0x11, 0x09, 0x07}
	} else {
		network.magic = []byte{0xf9, 0xbe, 0xb4, 0xd9}
	}

	return network
}

// ParseNetwork parses raw network message bytes and returns a NetworkEnvelope.
func ParseNetwork(rawData []byte, testnet bool) *NetworkEnvelope {
	reader := bytes.NewReader(rawData)
	bufReader := bufio.NewReader(reader)

	magic := make([]byte, 4)
	n, err := io.ReadFull(bufReader, magic)
	if err != nil {
		panic(err)
	}
	if n == 0 {
		panic("connection reset!")
	}

	var expectedMagic []byte

	if testnet {
		expectedMagic = []byte{0x0b, 0x11, 0x09, 0x07}
	} else {
		expectedMagic = []byte{0xf9, 0xbe, 0xb4, 0xd9}
	}
	if bytes.Equal(magic, expectedMagic) != true {
		panic("magic is not right")
	}

	command := make([]byte, 12)
	_, err = io.ReadFull(bufReader, command)
	if err != nil {
		panic(err)
	}

	payloadLenBuf := make([]byte, 4)
	_, err = io.ReadFull(bufReader, payloadLenBuf)
	if err != nil {
		panic(err)
	}
	payloadLen := new(big.Int)
	payloadLen.SetBytes(tx.ReverseByteSlice(payloadLenBuf))
	checksum := make([]byte, 4)
	_, err = io.ReadFull(bufReader, checksum)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, payloadLen.Int64())
	_, err = io.ReadFull(bufReader, payload)
	if err != nil {
		panic(err)
	}

	calculatedChecksum := ecc.Hash256(string(payload))[0:4]
	if !bytes.Equal(checksum, calculatedChecksum) {
		panic("checksum dose not match")
	}

	return NewNetworkEnvelope(command, payload, testnet)
}

// String returns a human-readable representation of the network envelope.
func (n *NetworkEnvelope) String() string {
	return fmt.Sprintf("%s : %x\n", string(n.command), n.payload)
}

// Serialize converts the NetworkEnvelope into bytes suitable for sending over the network.
func (n *NetworkEnvelope) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result, n.magic...)

	command := make([]byte, 0)
	command = append(command, n.command...)

	commandLen := len(command)
	if len(command) < 12 {
		// bug fix, we need to padd command to 12 bytes long
		for i := 0; i < 12-commandLen; i++ {
			command = append(command, 0x00)
		}
	}
	result = append(result, command...)

	payLoadLen := big.NewInt(int64(len(n.payload)))
	result = append(result, tx.BigIntToLittleEndian(payLoadLen, tx.LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, ecc.Hash256(string(n.payload))[0:4]...)
	result = append(result, n.payload...)

	return result
}
