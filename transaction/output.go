package transaction

import (
	"bufio"
	"math/big"
)

// Represents a transaction output
type TransactionOutput struct {
	amount       *big.Int
	scriptPubKey *ScriptSig
	reader       *bufio.Reader
}

// Creates a new transaction output from a binary reader
func NewTransactionOutput(reader *bufio.Reader) *TransactionOutput {
	return &TransactionOutput{
		reader: reader,
	}
}
