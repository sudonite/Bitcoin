package transaction

import (
	"bufio"
	"fmt"
	"math/big"
)

// Represents a transaction output
type TransactionOutput struct {
	amount       *big.Int
	scriptPubKey *ScriptSig
}

// Creates a new transaction output from a binary reader
func NewTransactionOutput(reader *bufio.Reader) *TransactionOutput {
	amountBuf := make([]byte, 8)
	reader.Read(amountBuf)
	amount := LittleEndianToBigInt(amountBuf, LITTLE_ENDIAN_8_BYTES)
	script := NewScriptSig(reader)
	return &TransactionOutput{
		amount:       amount,
		scriptPubKey: script,
	}
}

// InitTransactionOutput creates a new transaction output with the given amount and locking script
func InitTransactionOutput(amount *big.Int, script *ScriptSig) *TransactionOutput {
	return &TransactionOutput{
		amount:       amount,
		scriptPubKey: script,
	}
}

// String returns a human-readable representation of the transaction output
func (t *TransactionOutput) String() string {
	return fmt.Sprintf("amount: %v\n scriptPubKey: %x\n", t.amount,
		t.scriptPubKey.Serialize())
}

// Serialize converts the TransactionOutput into raw bytes
func (t *TransactionOutput) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result,
		BigIntToLittleEndian(t.amount, LITTLE_ENDIAN_8_BYTES)...)
	result = append(result, t.scriptPubKey.Serialize()...)
	return result
}
