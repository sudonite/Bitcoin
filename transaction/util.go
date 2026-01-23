package transaction

import (
	"bufio"
	"fmt"
	"math/big"

	"encoding/binary"

	"github.com/tsuna/endian"
)

const (
	STASHI_PER_BITCOIN = 100000000
)

// Enum for fixed little-endian byte lengths
type LITTLE_ENDIAN_LENGTH int

const (
	LITTLE_ENDIAN_2_BYTES = iota
	LITTLE_ENDIAN_4_BYTES
	LITTLE_ENDIAN_8_BYTES
)

// Converts a big.Int to little-endian bytes of fixed length
func BigIntToLittleEndian(v *big.Int, length LITTLE_ENDIAN_LENGTH) []byte {
	switch length {
	case LITTLE_ENDIAN_2_BYTES:
		bin := make([]byte, 2)
		binary.LittleEndian.PutUint16(bin, uint16(v.Uint64()))
		return bin
	case LITTLE_ENDIAN_4_BYTES:
		bin := make([]byte, 4)
		binary.LittleEndian.PutUint32(bin, uint32(v.Uint64()))
		return bin
	case LITTLE_ENDIAN_8_BYTES:
		bin := make([]byte, 8)
		binary.LittleEndian.PutUint64(bin, v.Uint64())
		return bin
	}

	return nil
}

// Converts little-endian bytes into a big.Int
func LittleEndianToBigInt(bytes []byte, length LITTLE_ENDIAN_LENGTH) *big.Int {
	switch length {
	case LITTLE_ENDIAN_2_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint16(uint16(p.Uint64()))
		return big.NewInt(int64(val))
	case LITTLE_ENDIAN_4_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint32(uint32(p.Uint64()))
		return big.NewInt(int64(val))
	case LITTLE_ENDIAN_8_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint64(uint64(p.Uint64()))
		return big.NewInt(int64(val))
	}

	return nil
}

// Reads a Bitcoin-style variable integer from a reader
func ReadVarint(reader *bufio.Reader) *big.Int {
	i := make([]byte, 1)
	reader.Read(i)
	v := new(big.Int).SetBytes(i)

	if v.Cmp(big.NewInt(0xfd)) < 0 {
		return v
	}

	if v.Cmp(big.NewInt(0xfd)) == 0 {
		i1 := make([]byte, 2)
		reader.Read(i1)
		return LittleEndianToBigInt(i1, LITTLE_ENDIAN_2_BYTES)
	}

	if v.Cmp(big.NewInt(0xfe)) == 0 {
		i1 := make([]byte, 4)
		reader.Read(i1)
		return LittleEndianToBigInt(i1, LITTLE_ENDIAN_4_BYTES)
	}

	i1 := make([]byte, 8)
	reader.Read(i1)
	return LittleEndianToBigInt(i1, LITTLE_ENDIAN_8_BYTES)
}

// Encodes a big.Int into Bitcoin varint format
func EncodeVarint(v *big.Int) []byte {
	if v.Cmp(big.NewInt(0xfd)) < 0 {
		vBytes := v.Bytes()
		if len(vBytes) != 0 {
			return []byte{vBytes[0]}
		}
		return []byte{0x00}
	} else if v.Cmp(big.NewInt(0x10000)) < 0 {
		buf := []byte{0xfd}
		vBuf := BigIntToLittleEndian(v, LITTLE_ENDIAN_2_BYTES)
		buf = append(buf, vBuf...)
		return buf
	} else if v.Cmp(big.NewInt(0x100000000)) < 0 {
		buf := []byte{0xfe}
		vBuf := BigIntToLittleEndian(v, LITTLE_ENDIAN_4_BYTES)
		buf = append(buf, vBuf...)
		return buf
	}

	p := new(big.Int)
	p.SetString("10000000000000000", 16)
	if v.Cmp(p) < 0 {
		buf := []byte{0xff}
		vBuf := BigIntToLittleEndian(v, LITTLE_ENDIAN_8_BYTES)
		buf = append(buf, vBuf...)
		return buf
	}

	panic(fmt.Sprintf("integer too large: %x\n", v))
}

// Reverses a byte slice
func ReverseByteSlice(bytes []byte) []byte {
	reverseBytes := []byte{}
	for i := len(bytes) - 1; i >= 0; i-- {
		reverseBytes = append(reverseBytes, bytes[i])
	}
	return reverseBytes
}

// P2pkScript creates a Pay-to-Public-Key-Hash (P2PKH) locking script
func P2pkScript(h160 []byte) *ScriptSig {
	scriptContent := [][]byte{[]byte{OP_DUP}, []byte{OP_HASH160}, h160, []byte{OP_EQUALVERIFY}, []byte{OP_CHECKSIG}}
	return InitScriptSig(scriptContent)
}
