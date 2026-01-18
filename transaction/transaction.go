package transaction

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
)

// Represents a Bitcoin transaction
type Transaction struct {
	version   *big.Int
	txInputs  []*TransactionInput
	txOutputs []*TransactionOutput
	lockTime  *big.Int
	testnet   bool
}

// Parses a raw transaction from binary data
func ParseTransaction(binary []byte) *Transaction {
	transaction := &Transaction{}
	reader := bytes.NewReader(binary)
	bufReader := bufio.NewReader(reader)

	verBuf := make([]byte, 4)
	bufReader.Read(verBuf)

	version := LittleEndianToBigInt(verBuf, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("transaction version: %x\n", version)
	transaction.version = version

	inputs := getInputCount(bufReader)
	transactionInputs := []*TransactionInput{}

	for i := 0; i < int(inputs.Int64()); i++ {
		input := NewTransactionInput(bufReader)
		transactionInputs = append(transactionInputs, input)
	}
	transaction.txInputs = transactionInputs

	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTransactionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	lockTimeBytes := make([]byte, 4)
	bufReader.Read(lockTimeBytes)
	transaction.lockTime = LittleEndianToBigInt(lockTimeBytes, LITTLE_ENDIAN_4_BYTES)

	return transaction
}

// GetScript returns the combined script (scriptSig + scriptPubKey) for the input at index `idx`
func (t *Transaction) GetScript(idx int, testnet bool) *ScriptSig {
	if idx < 0 || idx >= len(t.txInputs) {
		panic("invalid index for transaction input")
	}

	txInput := t.txInputs[idx]
	return txInput.Script(testnet)
}

// Reads the transaction input count, handling possible SegWit marker
func getInputCount(bufReader *bufio.Reader) *big.Int {
	firstByte, err := bufReader.Peek(1)
	if err != nil {
		panic(err)
	}

	if firstByte[0] == 0x00 {
		skipBuf := make([]byte, 2)
		_, err := bufReader.Read(skipBuf)
		if err != nil {
			panic(err)
		}
	}

	count := ReadVarint(bufReader)
	fmt.Printf("input count is: %x\n", count)
	return count
}
