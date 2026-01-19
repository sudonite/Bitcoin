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
	// first 32 bytes are hash256 of previous transation
	transactionInput := &TransactionInput{}
	transactionInput.fetcher = NewTransactionFetcher()

	previousTransaction := make([]byte, 32)
	reader.Read(previousTransaction)
	// convert it from little endian to big endian
	// reverse the byte array [0x01, 0x02, 0x03, 0x04] -> [0x04, 0x03, 0x02, 0x01]
	transactionInput.previousTransactionID = ReverseByteSlice(previousTransaction)

	// 4 bytes for previous transaction index
	idx := make([]byte, 4)
	reader.Read(idx)
	transactionInput.previousTransactionIndex = LittleEndianToBigInt(idx, LITTLE_ENDIAN_4_BYTES)

	transactionInput.scriptSig = NewScriptSig(reader)

	// last four bytes for sequence
	seqBytes := make([]byte, 4)
	reader.Read(seqBytes)
	transactionInput.sequence = LittleEndianToBigInt(seqBytes, LITTLE_ENDIAN_4_BYTES)

	return transactionInput
}

// InitTransactionInput creates a new transaction input referencing a previous output
func InitTransactionInput(previousTx []byte, previousIndex *big.Int) *TransactionInput {
	return &TransactionInput{
		previousTransactionID:    previousTx,
		previousTransactionIndex: previousIndex,
		scriptSig:                nil,
		sequence:                 big.NewInt(0xffffffff),
	}
}

// String returns a human-readable representation of the transaction input
func (t *TransactionInput) String() string {
	return fmt.Sprintf("previous transaction: %x\n previous tx index: %x\n", t.previousTransactionID, t.previousTransactionIndex)
}

// SetScriptSig sets the scriptSig for this transaction input
func (t *TransactionInput) SetScriptSig(sig *ScriptSig) {
	t.scriptSig = sig
}

// Returns the value (amount in satoshis) of the referenced UTXO
func (t *TransactionInput) Value(testnet bool) *big.Int {
	tx := t.getPreviousTx(testnet)
	return tx.txOutputs[t.previousTransactionIndex.Int64()].amount
}

// Script returns the combined script (scriptSig + scriptPubKey) for this input.
func (t *TransactionInput) Script(testnet bool) *ScriptSig {
	previousTxID := fmt.Sprintf("%x", t.previousTransactionID)
	previousTX := t.fetcher.Fetch(previousTxID, testnet)
	tx := ParseTransaction(previousTX)

	scriptPubKey := tx.txOutputs[t.previousTransactionIndex.Int64()].scriptPubKey
	return t.scriptSig.Add(scriptPubKey)
}

// Serialize converts the transaction input into its binary format.
func (t *TransactionInput) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result, ReverseByteSlice(t.previousTransactionID)...)
	result = append(result,
		BigIntToLittleEndian(t.previousTransactionIndex,
			LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, t.scriptSig.Serialize()...)
	result = append(result,
		BigIntToLittleEndian(t.sequence, LITTLE_ENDIAN_4_BYTES)...)
	return result
}

// ReplaceWithScriptPubKey replaces the current scriptSig with the referenced output's scriptPubKey
func (t *TransactionInput) ReplaceWithScriptPubKey(testnet bool) {
	t.scriptSig = t.scriptPubKey(testnet)
}

// scriptPubKey retrieves the locking script (scriptPubKey) from the referenced previous transaction output
func (t *TransactionInput) scriptPubKey(testnet bool) *ScriptSig {
	tx := t.getPreviousTx(testnet)
	return tx.txOutputs[t.previousTransactionIndex.Int64()].scriptPubKey
}

// getPreviousTx fetches and parses the previous transaction referenced by this input
func (t *TransactionInput) getPreviousTx(testnet bool) *Transaction {
	previousTxID := fmt.Sprintf("%x", t.previousTransactionID)
	previousTX := t.fetcher.Fetch(previousTxID, testnet)
	tx := ParseTransaction(previousTX)
	return tx
}
