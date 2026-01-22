package transaction

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
)

// Represents a Bitcoin script
type ScriptSig struct {
	cmds          [][]byte
	bitcoinOpCode *BitcoinOpCode
}

// Script push-data opcode constants
const (
	SCRIPT_DATA_LENGTH_BEGIN = 1
	SCRIPT_DATA_LENGTH_END   = 75
	OP_PUSHDATA1             = 76
	OP_PUSHDATA2             = 77
)

// Parses a script from a binary reader
func NewScriptSig(reader *bufio.Reader) *ScriptSig {
	cmds := [][]byte{}

	scriptLen := ReadVarint(reader).Int64()
	count := int64(0)
	current := make([]byte, 1)
	var current_byte byte

	for count < scriptLen {
		io.ReadFull(reader, current)
		count += 1
		current_byte = current[0]

		if current_byte >= SCRIPT_DATA_LENGTH_BEGIN && current_byte <= SCRIPT_DATA_LENGTH_END {
			// push the following bytes as data on the stack
			data := make([]byte, current_byte)
			io.ReadFull(reader, data)
			cmds = append(cmds, data)
			count += int64(current_byte)
		} else if current_byte == OP_PUSHDATA1 {
			length := make([]byte, 1)
			io.ReadFull(reader, length)
			data := make([]byte, length[0])
			reader.Read(data)
			cmds = append(cmds, data)
			count += int64(length[0] + 1)
		} else if current_byte == OP_PUSHDATA2 {
			lenBuf := make([]byte, 2)
			io.ReadFull(reader, lenBuf)
			length := LittleEndianToBigInt(lenBuf, LITTLE_ENDIAN_2_BYTES)
			data := make([]byte, length.Int64())
			cmds = append(cmds, data)
			count += length.Int64() + 2
		} else {
			// current byte is an instruction
			cmds = append(cmds, []byte{current_byte})
		}
	}

	if count != scriptLen {
		panic("parsing script field failed")
	}

	return InitScriptSig(cmds)
}

// Creates a new ScriptSig from a list of commands
func InitScriptSig(cmds [][]byte) *ScriptSig {
	bitcoinOpCode := NewBitcoinOpCode()
	bitcoinOpCode.cmds = cmds
	return &ScriptSig{
		bitcoinOpCode: bitcoinOpCode,
	}
}

// Executes all commands in the ScriptSig against the given message hash `z`
func (s *ScriptSig) Evaluate(z []byte) bool {
	for s.bitcoinOpCode.HasCmd() {
		cmd := s.bitcoinOpCode.RemoveCmd()
		if len(cmd) == 1 {
			//this is an op code, run it
			opRes := s.bitcoinOpCode.ExecuteOperation(int(cmd[0]), z)
			if opRes != true {
				return false
			}
		} else {
			s.bitcoinOpCode.AppendDataElement(cmd)
		}
	}

	if len(s.bitcoinOpCode.stack) == 0 {
		return false
	}

	if len(s.bitcoinOpCode.stack[len(s.bitcoinOpCode.stack)-1]) == 0 {
		return false
	}

	return true
}

// Serializes the script with length prefix (varint)
func (s *ScriptSig) Serialize() []byte {
	rawResult := s.rawSerialize()
	total := len(rawResult)
	result := []byte{}

	// encode the total length of the script at the head
	fmt.Printf("total: %+v\n", total)
	result = append(result, EncodeVarint(big.NewInt(int64(total)))...)
	result = append(result, rawResult...)
	return result
}

// Combines two ScriptSig scripts into a single ScriptSig
func (s *ScriptSig) Add(script *ScriptSig) *ScriptSig {
	cmds := make([][]byte, 0)
	cmds = append(cmds, s.bitcoinOpCode.cmds...)
	cmds = append(cmds, script.bitcoinOpCode.cmds...)
	return InitScriptSig(cmds)
}

// Serializes script commands without length prefix
func (s *ScriptSig) rawSerialize() []byte {
	result := []byte{}
	for _, cmd := range s.bitcoinOpCode.cmds {
		if len(cmd) == 1 {
			// only one byte means its an instruction
			result = append(result, cmd...)
		} else {
			length := len(cmd)
			if length <= SCRIPT_DATA_LENGTH_END {
				// length in [0x01, 0x4b]
				result = append(result, byte(length))
			} else if length > SCRIPT_DATA_LENGTH_END && length < 0x100 {
				// this is OP_PUSHDATA1 command,
				// push the command and then the next byte is the length of the data
				result = append(result, OP_PUSHDATA1)
				result = append(result, byte(length))
			} else if length >= 0x100 && length <= 520 {
				result = append(result, OP_PUSHDATA2)
				lenBuf := BigIntToLittleEndian(big.NewInt(int64(length)), LITTLE_ENDIAN_2_BYTES)
				result = append(result, lenBuf...)
			} else {
				panic("too long an cmd")
			}

			// append the chunk of data with given length
			result = append(result, cmd...)
		}
	}

	return result
}
