package bloomfilter

import (
	"math/big"

	"github.com/sudonite/bitcoin/transaction"
)

// Data represents a single "getdata" item, consisting of a type and an identifier (usually txid or block hash)
type Data struct {
	dataTye    []byte
	identifier []byte
}

// GetDataMessage represents a Bitcoin "getdata" network message
type GetDataMessage struct {
	command string
	data    []Data
}

// NewGetDataMessage creates a new empty getdata message
func NewGetDataMessage() *GetDataMessage {
	getDataMsg := &GetDataMessage{
		command: "getdata",
		data:    make([]Data, 0),
	}

	return getDataMsg
}

// AddData appends a new data request item to the message
func (g *GetDataMessage) AddData(dataType []byte, identifier []byte) {
	g.data = append(g.data, Data{
		dataTye:    dataType,
		identifier: identifier,
	})
}

// Command returns the network command name ("getdata")
func (g *GetDataMessage) Command() string {
	return g.command
}

// Serialize converts the GetDataMessage into raw bytes suitable for sending over the network
func (g *GetDataMessage) Serialize() []byte {
	result := make([]byte, 0)
	dataCount := big.NewInt(int64(len(g.data)))
	result = append(result, transaction.EncodeVarint(dataCount)...)
	for _, item := range g.data {
		dataType := new(big.Int)
		dataType.SetBytes(item.dataTye)
		result = append(result, transaction.BigIntToLittleEndian(dataType,
			transaction.LITTLE_ENDIAN_4_BYTES)...)
		result = append(result, transaction.ReverseByteSlice(item.identifier)...)
	}

	return result
}
