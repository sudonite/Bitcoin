package merkletree

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/sudonite/bitcoin/transaction"
	"golang.org/x/example/hello/reverse"
)

// MerkleBlock represents a compact block header with partial Merkle tree data.
type MerkleBlock struct {
	version           *big.Int
	previousBlock     []byte
	merkleRoot        []byte
	timeStamp         *big.Int
	bits              []byte
	nonce             []byte
	totalTransactions *big.Int
	numHashes         *big.Int
	hashes            [][]byte
	flagBits          []byte
}

// ErrorPanic panics with a message if the error is non-nil.
func ErrorPanic(err error, msg string) {
	if err != nil {
		panic(msg)
	}
}

// BytesToBitsField converts a byte array into a list of reversed bit strings.
func BytesToBitsField(bytes []byte) []string {
	flagBits := make([]string, 0)
	for _, byteVal := range bytes {
		//bug fix, need to reverse the ordering of bits!
		flagBits = append(flagBits, reverse.String(fmt.Sprintf("%08b", byteVal)))
	}

	return flagBits
}

// ParseMerkleBlock parses a raw payload into a MerkleBlock struct.
func ParseMerkleBlock(payload []byte) *MerkleBlock {
	merkleBlock := &MerkleBlock{}
	reader := bytes.NewReader(payload)
	bufReader := bufio.NewReader(reader)
	version := make([]byte, 4)
	_, err := bufReader.Read(version)
	ErrorPanic(err, "MerkleBlock read version")
	merkleBlock.version = transaction.LittleEndianToBigInt(version, transaction.LITTLE_ENDIAN_4_BYTES)

	prevBlock := make([]byte, 32)
	_, err = bufReader.Read(prevBlock)
	ErrorPanic(err, "MerkleBlock read previous block")
	merkleBlock.previousBlock = transaction.ReverseByteSlice(prevBlock)

	merkleRoot := make([]byte, 32)
	_, err = bufReader.Read(merkleRoot)
	ErrorPanic(err, "MerkleBlock read merkle root")
	merkleBlock.merkleRoot = transaction.ReverseByteSlice(merkleRoot)

	timeStamp := make([]byte, 4)
	_, err = bufReader.Read(timeStamp)
	ErrorPanic(err, "MerkleBlock read time stamp")
	merkleBlock.timeStamp = transaction.LittleEndianToBigInt(timeStamp, transaction.LITTLE_ENDIAN_4_BYTES)

	bits := make([]byte, 4)
	_, err = bufReader.Read(bits)
	ErrorPanic(err, "MerkleBlock read bits")
	merkleBlock.bits = bits

	nonce := make([]byte, 4)
	_, err = bufReader.Read(nonce)
	ErrorPanic(err, "MerkleBlock read nonce")
	merkleBlock.nonce = nonce

	total := make([]byte, 4)
	_, err = bufReader.Read(total)
	ErrorPanic(err, "MerkleBloc read total")
	merkleBlock.totalTransactions = transaction.LittleEndianToBigInt(total, transaction.LITTLE_ENDIAN_4_BYTES)

	numHashes := transaction.ReadVarint(bufReader)
	merkleBlock.numHashes = numHashes

	hashes := make([][]byte, 0)
	for i := 0; i < int(numHashes.Int64()); i++ {
		hash := make([]byte, 32)
		_, err = bufReader.Read(hash)
		ErrorPanic(err, "MerkleBlock read hash")
		hashes = append(hashes, transaction.ReverseByteSlice(hash))
	}
	merkleBlock.hashes = hashes

	flagLen := transaction.ReadVarint(bufReader)
	flags := make([]byte, flagLen.Int64())
	_, err = bufReader.Read(flags)
	ErrorPanic(err, "MerkleBlock read flags")
	merkleBlock.flagBits = flags

	return merkleBlock
}

// String returns a human-readable string representation of the MerkleBlock.
func (m *MerkleBlock) String() string {
	result := make([]string, 0)
	result = append(result, fmt.Sprintf("version: %x", m.version))
	result = append(result, fmt.Sprintf("previous block: %x", m.previousBlock))
	result = append(result, fmt.Sprintf("merkle root: %x", m.merkleRoot))
	bitsString := strings.Join(BytesToBitsField(m.bits), ",")
	result = append(result, fmt.Sprintf("bits: %s", bitsString))
	result = append(result, fmt.Sprintf("nonce:%x", m.nonce))
	result = append(result, fmt.Sprintf("total tx: %x", m.totalTransactions.Int64()))
	result = append(result, fmt.Sprintf("number of hashes:%d", m.numHashes.Int64()))
	for i := 0; i < int(m.numHashes.Int64()); i++ {
		result = append(result, fmt.Sprintf("%x,", m.hashes[i]))
	}

	flagToBits := strings.Join(BytesToBitsField(m.flagBits), "")
	result = append(result, fmt.Sprintf("flags: %x", flagToBits))

	return strings.Join(result, "\n")
}

// IsValid checks if the Merkle root reconstructed from the partial tree matches the block's merkleRoot.
func (m *MerkleBlock) IsValid() bool {
	flagBits := strings.Join(BytesToBitsField(m.flagBits), "")
	merkleTree := InitEmptyMerkleTree(int(m.totalTransactions.Int64()))
	// when compute merkle root, we need all hash in little endian format
	hashes := make([][]byte, 0)
	for _, hash := range m.hashes {
		hashes = append(hashes, transaction.ReverseByteSlice(hash))
	}
	merkleTree.PopluateTree(flagBits, hashes)
	// need to reverse the byte order of the root
	return bytes.Equal(m.merkleRoot, transaction.ReverseByteSlice(merkleTree.Root()))
}
