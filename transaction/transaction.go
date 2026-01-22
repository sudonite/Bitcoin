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
	SIGHASH_ALL = 1
)

// Represents a Bitcoin transaction
type Transaction struct {
	version   *big.Int
	txInputs  []*TransactionInput
	txOutputs []*TransactionOutput
	lockTime  *big.Int
	testnet   bool
}

// InitTransaction creates a new Bitcoin transaction with the given parameters
func InitTransaction(version *big.Int, txInputs []*TransactionInput,
	txOutputs []*TransactionOutput, lockTime *big.Int, testnet bool) *Transaction {
	return &Transaction{
		version:   version,
		txInputs:  txInputs,
		txOutputs: txOutputs,
		lockTime:  lockTime,
		testnet:   testnet,
	}
}

// String returns a human-readable representation of the transaction
func (t *Transaction) String() string {
	txIns := ""
	for i := 0; i < len(t.txInputs); i++ {
		txIns += t.txInputs[i].String()
		txIns += "\n"
	}

	txOuts := ""
	for i := 0; i < len(t.txOutputs); i++ {
		txOuts += t.txOutputs[i].String()
		txOuts += "\n"
	}

	return fmt.Sprintf("tx: version: %x\n transaction inputs\n:%s\n transaction outputs:\n %s\n, locktime: %x\n",
		t.version, txIns, txOuts, t.lockTime)
}

// Parses a raw transaction from binary data
func ParseTransaction(binary []byte) *Transaction {
	transaction := &Transaction{}
	reader := bytes.NewReader(binary)
	bufReader := bufio.NewReader(reader)

	verBuf := make([]byte, 4)
	io.ReadFull(bufReader, verBuf)

	version := LittleEndianToBigInt(verBuf, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("transaction version:%x\n", version)
	transaction.version = version

	inputs := getInputCount(bufReader)
	transactionInputs := []*TransactionInput{}
	for i := 0; i < int(inputs.Int64()); i++ {
		input := NewTransactionInput(bufReader)
		transactionInputs = append(transactionInputs, input)
	}
	transaction.txInputs = transactionInputs

	//read output counts
	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTransactionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	//get last four bytes for lock time
	lockTimeBytes := make([]byte, 4)
	io.ReadFull(bufReader, lockTimeBytes)
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

// Fee calculates the transaction fee as (sum of inputs - sum of outputs)
func (t *Transaction) Fee() *big.Int {
	inputSum := big.NewInt(0)
	outputSum := big.NewInt(0)

	for i := 0; i < len(t.txInputs); i++ {
		addOp := new(big.Int)
		value := t.txInputs[i].Value(t.testnet)
		inputSum = addOp.Add(inputSum, value)
	}

	for i := 0; i < len(t.txOutputs); i++ {
		addOp := new(big.Int)
		outputSum = addOp.Add(outputSum, t.txOutputs[i].amount)
	}

	opSub := new(big.Int)
	return opSub.Sub(inputSum, outputSum)
}

// SerializeWithSign serializes the transaction for signing a specific input
func (t *Transaction) SerializeWithSign(inputIdx int) []byte {
	signBinary := make([]byte, 0)
	signBinary = append(signBinary, BigIntToLittleEndian(t.version, LITTLE_ENDIAN_4_BYTES)...)

	inputCount := big.NewInt(int64(len(t.txInputs)))
	signBinary = append(signBinary, EncodeVarint(inputCount)...)

	for i := 0; i < len(t.txInputs); i++ {
		if i == inputIdx {
			t.txInputs[i].ReplaceWithScriptPubKey(t.testnet)
			signBinary = append(signBinary, t.txInputs[i].Serialize()...)
		} else {
			signBinary = append(signBinary, t.txInputs[i].Serialize()...)
		}
	}

	outputCount := big.NewInt(int64(len(t.txOutputs)))
	signBinary = append(signBinary, EncodeVarint(outputCount)...)
	for i := 0; i < len(t.txOutputs); i++ {
		signBinary = append(signBinary, t.txOutputs[i].Serialize()...)
	}

	signBinary = append(signBinary, BigIntToLittleEndian(t.lockTime, LITTLE_ENDIAN_4_BYTES)...)
	signBinary = append(signBinary,
		BigIntToLittleEndian(big.NewInt(int64(SIGHASH_ALL)), LITTLE_ENDIAN_4_BYTES)...)

	return signBinary
}

// SignHash computes the double-SHA256 hash of the serialized transaction for signing
func (t *Transaction) SignHash(inputIdx int) []byte {
	signBinary := t.SerializeWithSign(inputIdx)
	// compute hash256 for the modified transaction binary
	h256 := ecc.Hash256(string(signBinary))
	return h256
}

// VerifyInput verifies a single input by executing its combined script
func (t *Transaction) VerifyInput(inputIndex int) bool {
	verifyScript := t.GetScript(inputIndex, t.testnet)
	z := t.SignHash(inputIndex)
	return verifyScript.Evaluate(z)
}

// Verify checks the entire transaction
func (t *Transaction) Verify() bool {
	if t.Fee().Cmp(big.NewInt(int64(0))) < 0 {
		return false
	}

	for i := 0; i < len(t.txInputs); i++ {
		if t.VerifyInput(i) != true {
			return false
		}
	}

	return true
}

// Reads the transaction input count, handling possible SegWit marker
func getInputCount(bufReader *bufio.Reader) *big.Int {
	firstByte, err := bufReader.Peek(1)
	if err != nil {
		panic(err)
	}

	if firstByte[0] == 0x00 {
		skipBuf := make([]byte, 2)
		_, err := io.ReadFull(bufReader, skipBuf)
		if err != nil {
			panic(err)
		}
	}

	count := ReadVarint(bufReader)
	fmt.Printf("input count is: %x\n", count)
	return count
}
