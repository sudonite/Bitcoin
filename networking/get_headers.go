package networking

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	tx "github.com/sudonite/bitcoin/transaction"
)

// GetHeaderMessage represents a "getheaders" message in the Bitcoin protocol
type GetHeaderMessage struct {
	command    string
	version    *big.Int
	numHashes  *big.Int
	startBlock []byte
	endBlock   []byte
}

// GetGenesisBlockHash returns the hash of the Bitcoin genesis block.
func GetGenesisBlockHash() []byte {
	genesisBlockRawData, err := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
	if err != nil {
		panic(err)
	}
	genesisBlock := tx.ParseBlock(genesisBlockRawData)
	return genesisBlock.Hash()
}

// NewGetHeaderMessage constructs a new GetHeaderMessage with a given starting block hash.
func NewGetHeaderMessage(startBlock []byte) *GetHeaderMessage {
	return &GetHeaderMessage{
		command:    "getheaders",
		version:    big.NewInt(70015),
		numHashes:  big.NewInt(1),
		startBlock: startBlock,
		endBlock:   make([]byte, 32),
	}
}

// Command returns the command string for the message.
func (g *GetHeaderMessage) Command() string {
	return g.command
}

// Serialize converts the GetHeaderMessage into bytes suitable for sending over the network.
func (g *GetHeaderMessage) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result, tx.BigIntToLittleEndian(g.version,
		tx.LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, tx.EncodeVarint(g.numHashes)...)
	result = append(result, tx.ReverseByteSlice(g.startBlock)...)
	result = append(result, tx.ReverseByteSlice(g.endBlock)...)
	return result
}

// LenOfVarint returns the number of bytes required to encode a varint.
func LenOfVarint(val *big.Int) int {
	shiftBytes := len(val.Bytes())
	if val.Cmp(big.NewInt(0xfd)) > 0 {
		// if the value bigger than 0xfd, we need to shift
		// one more byte
		shiftBytes += 1
	}

	return shiftBytes
}

// ParseGetHeader parses raw "headers" message data and returns a slice of blocks.
func ParseGetHeader(rawData []byte) []*tx.Block {
	reader := bytes.NewReader(rawData)
	bufReader := bufio.NewReader(reader)
	numHeaders := tx.ReadVarint(bufReader)
	fmt.Printf("header count:%d\n", numHeaders.Int64())
	shiftBytes := LenOfVarint(numHeaders)
	rawData = rawData[shiftBytes:]
	blocks := make([]*tx.Block, 0)

	for i := 0; i < int(numHeaders.Int64()); i++ {
		block := tx.ParseBlock(rawData)
		blocks = append(blocks, block)

		rawData = rawData[len(block.Serialize()):]
		reader := bytes.NewReader(rawData)
		bufReader := bufio.NewReader(reader)
		numTxs := tx.ReadVarint(bufReader)
		if numTxs.Cmp(big.NewInt(0)) != 0 {
			// number of transaction should be 0
			panic("number of transaction is not 0")
		}

		shift := LenOfVarint(numTxs)
		if shift == 0 {
			shift = 1
		}
		rawData = rawData[shift:]
	}
	return blocks
}
