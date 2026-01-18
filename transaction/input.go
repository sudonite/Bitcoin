package transaction

import (
	"bufio"
	"fmt"
	"math/big"
)

// Represents a transaction input
type TransactionInput struct {
	previousTransactionID    []byte
	previousTransactionIndex *big.Int
	scriptSig                *ScriptSig
	sequence                 *big.Int
	fetcher                  *TransactionFetcher
}

// Parses a transaction input from a binary reader
func NewTransactionInput(reader *bufio.Reader) *TransactionInput {
	transactionInput := &TransactionInput{}
	transactionInput.fetcher = NewTransactionFetcher()
	previousTransaction := make([]byte, 32)
	reader.Read(previousTransaction)
	transactionInput.previousTransactionID = reverseByteSlice(previousTransaction)
	fmt.Printf("previous transaction ID: %x\n", transactionInput.previousTransactionID)

	idx := make([]byte, 4)
	reader.Read(idx)
	transactionInput.previousTransactionIndex = LittleEndianToBigInt(idx, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("previous transaction index: %x\n", transactionInput.previousTransactionIndex)

	transactionInput.scriptSig = NewScriptSig(reader)
	scriptBuf := transactionInput.scriptSig.Serialize()
	fmt.Printf("script byte: %x\n", scriptBuf)

	seqBytes := make([]byte, 4)
	reader.Read(seqBytes)
	transactionInput.sequence = LittleEndianToBigInt(seqBytes, LITTLE_ENDIAN_4_BYTES)

	return transactionInput
}

// Returns the value (amount in satoshis) of the referenced UTXO
func (t *TransactionInput) Value(testnet bool) *big.Int {
	previousTxID := fmt.Sprintf("%x", t.previousTransactionID)
	previousTx := t.fetcher.Fetch(previousTxID, testnet)
	tx := ParseTransaction(previousTx)

	return tx.txOutputs[t.previousTransactionIndex.Int64()].amount
}

// Reverses a byte slice
func reverseByteSlice(bytes []byte) []byte {
	reverseBytes := []byte{}
	for i := len(bytes) - 1; i >= 0; i-- {
		reverseBytes = append(reverseBytes, bytes[i])
	}
	return reverseBytes
}
