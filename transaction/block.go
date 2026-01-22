package transaction

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

const (
	TWO_WEEKS = 60 * 60 * 24 * 14
)

// ComputeNewTarget calculates the new difficulty target based on the first and last block timestamps
func ComputeNewTarget(firstBlockBytes []byte, lastBlockBytes []byte) *big.Int {
	firstBlock := ParseBlock(firstBlockBytes)
	lastBlock := ParseBlock(lastBlockBytes)

	firstBlockTime := new(big.Int)
	firstBlockTime.SetBytes(firstBlock.timeStamp)
	lastBlockTime := new(big.Int)
	lastBlockTime.SetBytes(lastBlock.timeStamp)

	var opSub big.Int
	timeDifferential := opSub.Sub(lastBlockTime, firstBlockTime)
	if timeDifferential.Cmp(big.NewInt(TWO_WEEKS*4)) > 0 {
		timeDifferential = big.NewInt(TWO_WEEKS * 4)
	}
	if timeDifferential.Cmp(big.NewInt(TWO_WEEKS/4)) < 0 {
		timeDifferential = big.NewInt(TWO_WEEKS / 4)
	}

	var opMul big.Int
	var opDiv big.Int
	newTarget := opDiv.Div(opMul.Mul(lastBlock.Target(), timeDifferential), big.NewInt(TWO_WEEKS))
	return newTarget
}

// TargetToBits converts a target integer to the compact "bits" format used in block headers
func TargetToBits(target *big.Int) []byte {
	targetBytes := target.Bytes()
	exponent := len(targetBytes)
	coefficient := targetBytes[0:3]
	bits := make([]byte, 0)
	bits = append(bits, ReverseByteSlice(coefficient)...)
	bits = append(bits, byte(exponent))
	return bits
}

// Block represents a Bitcoin block header
type Block struct {
	version         []byte
	previousBlockID []byte
	merkleRoot      []byte
	timeStamp       []byte
	bits            []byte
	nonce           []byte
}

// ParseBlock reads a raw block header and returns a Block struct
func ParseBlock(rawBlock []byte) *Block {
	block := &Block{}

	reader := bytes.NewReader(rawBlock)
	bufReader := bufio.NewReader(reader)
	buffer := make([]byte, 4)
	io.ReadFull(bufReader, buffer)
	block.version = ReverseByteSlice(buffer)

	buffer = make([]byte, 32)
	io.ReadFull(bufReader, buffer)
	block.previousBlockID = ReverseByteSlice(buffer)

	buffer = make([]byte, 32)
	io.ReadFull(bufReader, buffer)
	block.merkleRoot = ReverseByteSlice(buffer)

	buffer = make([]byte, 4)
	io.ReadFull(bufReader, buffer)
	block.timeStamp = ReverseByteSlice(buffer)

	buffer = make([]byte, 4)
	io.ReadFull(bufReader, buffer)
	block.bits = buffer

	buffer = make([]byte, 4)
	io.ReadFull(bufReader, buffer)
	block.nonce = buffer

	return block
}

// Serialize converts a Block struct back into raw bytes
func (b *Block) Serialize() []byte {
	result := make([]byte, 0)
	version := new(big.Int)
	version.SetBytes(b.version)
	result = append(result, BigIntToLittleEndian(version, LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, ReverseByteSlice(b.previousBlockID)...)
	result = append(result, ReverseByteSlice(b.merkleRoot)...)

	timeStamp := new(big.Int)
	timeStamp.SetBytes(b.timeStamp)
	result = append(result, BigIntToLittleEndian(timeStamp, LITTLE_ENDIAN_4_BYTES)...)

	result = append(result, b.bits...)
	result = append(result, b.nonce...)

	return result
}

// Hash returns the double SHA256 hash of the block header
func (b *Block) Hash() []byte {
	s := b.Serialize()
	sha := ecc.Hash256(string(s))
	return ReverseByteSlice(sha)
}

// String returns a human-readable representation of the block header
func (b *Block) String() string {
	s := fmt.Sprintf("version:%x\nprevious block id:%x\nmerkle root:%x\ntime stamp:%x\nbits:%x\nnonce:%x\nhash:%x\n",
		b.version, b.previousBlockID, b.merkleRoot, b.timeStamp, b.bits, b.nonce, b.Hash())
	return s
}

// Bip9 checks if the block signals support for BIP9
func (b *Block) Bip9() bool {
	// is the miner support BIP0009
	version := new(big.Int)
	version.SetBytes(b.version)
	ver := version.Int64()
	return (ver >> 29) == 0b001
}

// Bip91 checks if the block signals support for BIP91
func (b *Block) Bip91() bool {
	// is support BIP0091
	version := new(big.Int)
	version.SetBytes(b.version)
	ver := version.Int64()
	return (ver >> 4 & 1) == 1
}

// Bip141 checks if the block signals support for BIP141
func (b *Block) Bip141() bool {
	// is support BIP0141
	version := new(big.Int)
	version.SetBytes(b.version)
	ver := version.Int64()
	return (ver >> 1 & 1) == 1
}

// Target calculates the proof-of-work target from the block's "bits" field.
func (b *Block) Target() *big.Int {
	// exponent - 3
	var opSub big.Int
	exponentPart := opSub.Sub(big.NewInt(int64(b.bits[len(b.bits)-1])), big.NewInt(int64(3)))
	// the most significant three bits is coefficient
	coefficientBuf := b.bits[0 : len(b.bits)-1]
	coefficientBytes := ReverseByteSlice(coefficientBuf)
	coefficient := new(big.Int)
	coefficient.SetBytes(coefficientBytes)
	var opPow big.Int
	var opMul big.Int
	exponent := opPow.Exp(big.NewInt(int64(256)), exponentPart, nil)
	result := opMul.Mul(coefficient, exponent)
	return result
}

// Difficulty returns the mining difficulty of the block based on its target.
func (b *Block) Difficulty() *big.Int {
	target := b.Target()
	var opMul big.Int
	var opExp big.Int
	var opDiv big.Int
	numerator := opMul.Mul(big.NewInt(0xffff), opExp.Exp(big.NewInt(256), big.NewInt(0x1d-3), nil))
	denominator := target
	difficulty := opDiv.Div(numerator, denominator)
	return difficulty
}
