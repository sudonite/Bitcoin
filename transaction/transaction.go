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
	segwit    bool
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
	reader := bytes.NewReader(binary)
	bufReader := bufio.NewReader(reader)

	verBuf := make([]byte, 4)
	io.ReadFull(bufReader, verBuf)

	segWitMarker := make([]byte, 1)
	io.ReadFull(bufReader, segWitMarker)

	reader = bytes.NewReader(binary)
	bufReader = bufio.NewReader(reader)
	if segWitMarker[0] == 0x00 {
		return parseSegwit(bufReader)
	}

	return parseLegacy(bufReader)
}

// SetTestnet marks the transaction as using Bitcoin testnet parameters
func (t *Transaction) SetTestnet() {
	t.testnet = true
}

// IsP2wpkh checks whether the given script matches a Pay-to-Witness-Public-Key-Hash (P2WPKH) pattern
func (t *Transaction) IsP2wpkh(script *ScriptSig) bool {
	if len(script.bitcoinOpCode.cmds) != 2 {
		return false
	}
	if script.bitcoinOpCode.cmds[0][0] != byte(OP_0) && len(script.bitcoinOpCode.cmds[1]) != 20 {
		return false
	}

	return true
}

// Serialize encodes the transaction into bytes, using SegWit or legacy format depending on the flag
func (t *Transaction) Serialize() []byte {
	if t.segwit {
		return t.serializeSegwit()
	}

	return t.serializeLegacy()
}

// Hash computes the transaction ID (txid) by double-SHA256 hashing the legacy serialization
func (t *Transaction) Hash() []byte {
	hash := ecc.Hash256(string(t.serializeLegacy()))
	return ReverseByteSlice(hash)
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
	if t.IsP2wpkh(verifyScript) != true {
		z := t.SignHash(inputIndex)
		return verifyScript.Evaluate(z)
	}

	// verify segwit transaction
	z := t.BIP143SigHash(inputIndex)
	witness := t.txInputs[inputIndex].witness
	verifyScript.SetWitness(witness)
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

// Checks the transaction is a CoinBase transacion
func (t *Transaction) IsCoinBase() bool {
	if len(t.txInputs) != 1 {
		return false
	}
	for i := 0; i < len(t.txInputs[0].previousTransactionID); i++ {
		if t.txInputs[0].previousTransactionID[i] != 0x00 {
			return false
		}
	}

	coinBaseIdx := big.NewInt(int64(0xffffffff))
	if t.txInputs[0].previousTransactionIndex.Cmp(coinBaseIdx) != 0 {
		return false
	}

	return true
}

// BIP143SigHash computes the signature hash for a SegWit (BIP-143) input, following the BIP-143 serialization rules for signing P2WPKH transactions.
func (t *Transaction) BIP143SigHash(inputIdx int) []byte {
	txInput := t.txInputs[inputIdx]
	// construct hash
	result := make([]byte, 0)
	result = append(result, BigIntToLittleEndian(t.version, LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, t.previousTxInBIP134Hash()...)
	result = append(result, t.previousHashSequence()...)
	result = append(result, ReverseByteSlice(txInput.previousTransactionID)...)
	result = append(result, BigIntToLittleEndian(txInput.previousTransactionIndex, LITTLE_ENDIAN_4_BYTES)...)
	script := t.GetScript(inputIdx, true)
	p2pkScript := P2pkhScript(script.bitcoinOpCode.cmds[1])
	result = append(result, p2pkScript.Serialize()...)
	result = append(result, BigIntToLittleEndian(txInput.Value(t.testnet), LITTLE_ENDIAN_8_BYTES)...)
	result = append(result, BigIntToLittleEndian(txInput.sequence, LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, t.txOutBIP134Hash()...)
	result = append(result, BigIntToLittleEndian(t.lockTime, LITTLE_ENDIAN_4_BYTES)...)
	sigHashAll := big.NewInt(int64(SIGHASH_ALL))
	result = append(result, BigIntToLittleEndian(sigHashAll, LITTLE_ENDIAN_4_BYTES)...)
	hashResult := ecc.Hash256(string(result))
	return hashResult
}

// previousTxInBIP134Hash computes the double-SHA256 hash of all input outpoints (previous transaction IDs and output indices), as required by BIP-143.
func (t *Transaction) previousTxInBIP134Hash() []byte {
	allPreviousOut := make([]byte, 0)
	for _, txIn := range t.txInputs {
		allPreviousOut = append(allPreviousOut, ReverseByteSlice(txIn.previousTransactionID)...)
		allPreviousOut = append(allPreviousOut, BigIntToLittleEndian(txIn.previousTransactionIndex, LITTLE_ENDIAN_4_BYTES)...)
	}
	hash := ecc.Hash256(string(allPreviousOut))
	return hash
}

// txOutBIP134Hash computes the double-SHA256 hash of all transaction outputs, used in the BIP-143 signature hash calculation.
func (t *Transaction) txOutBIP134Hash() []byte {
	hashOut := make([]byte, 0)
	for _, txOut := range t.txOutputs {
		hashOut = append(hashOut, txOut.Serialize()...)
	}

	return ecc.Hash256(string(hashOut))
}

// previousHashSequence computes the double-SHA256 hash of all input sequence numbers, as required by the BIP-143 signature hashing algorithm.
func (t *Transaction) previousHashSequence() []byte {
	allSequence := make([]byte, 0)
	for _, txIn := range t.txInputs {
		allSequence = append(allSequence, BigIntToLittleEndian(txIn.sequence, LITTLE_ENDIAN_4_BYTES)...)
	}
	hash := ecc.Hash256(string(allSequence))
	return hash
}

// serializeSegwit serializes the transaction using the SegWit format, including marker, flag, and witness data.
func (t *Transaction) serializeSegwit() []byte {
	result := make([]byte, 0)
	result = append(result, BigIntToLittleEndian(t.version, LITTLE_ENDIAN_4_BYTES)...)
	result = append(result, []byte{0x00, 0x01}...)
	inputCount := big.NewInt(int64(len(t.txInputs)))
	result = append(result, EncodeVarint(inputCount)...)
	for _, txInput := range t.txInputs {
		result = append(result, txInput.Serialize()...)
	}

	outputCount := big.NewInt(int64(len(t.txOutputs)))
	result = append(result, EncodeVarint(outputCount)...)
	for _, txOutput := range t.txOutputs {
		result = append(result, txOutput.Serialize()...)
	}

	for _, txInput := range t.txInputs {
		itemCount := big.NewInt(int64(len(txInput.witness)))
		result = append(result, EncodeVarint(itemCount)...)
		for _, item := range txInput.witness {
			itemLen := big.NewInt(int64(len(item)))
			result = append(result, EncodeVarint(itemLen)...)
			result = append(result, item...)
		}
	}

	result = append(result, BigIntToLittleEndian(t.lockTime, LITTLE_ENDIAN_4_BYTES)...)
	return result
}

// serializeLegacy serializes the transaction in the pre-SegWit (legacy) format without witness data.
func (t *Transaction) serializeLegacy() []byte {
	result := make([]byte, 0)
	result = append(result, BigIntToLittleEndian(t.version, LITTLE_ENDIAN_4_BYTES)...)

	inputCount := big.NewInt(int64(len(t.txInputs)))
	result = append(result, EncodeVarint(inputCount)...)

	for i := 0; i < len(t.txInputs); i++ {
		result = append(result, t.txInputs[i].Serialize()...)
	}

	outputCount := big.NewInt(int64(len(t.txOutputs)))
	result = append(result, EncodeVarint(outputCount)...)
	for i := 0; i < len(t.txOutputs); i++ {
		result = append(result, t.txOutputs[i].Serialize()...)
	}

	result = append(result, BigIntToLittleEndian(t.lockTime, LITTLE_ENDIAN_4_BYTES)...)

	return result
}

// P2pkhScript builds a standard Pay-to-Public-Key-Hash (P2PKH) locking script from a hash160.
func P2pkhScript(h160 []byte) *ScriptSig {
	cmd := make([][]byte, 0)
	cmd = append(cmd, []byte{OP_DUP})
	cmd = append(cmd, []byte{OP_HASH160})
	cmd = append(cmd, h160)
	cmd = append(cmd, []byte{OP_EQUALVERIFY})
	cmd = append(cmd, []byte{OP_CHECKSIG})
	return InitScriptSig(cmd)
}

// Reads the transaction input count, handling possible SegWit marker
func getInputCount(bufReader *bufio.Reader) *big.Int {
	count := ReadVarint(bufReader)
	fmt.Printf("input count is: %x\n", count)
	return count
}

// parseLegacy parses a legacy (non-SegWit) Bitcoin transaction from the reader.
func parseLegacy(bufReader *bufio.Reader) *Transaction {
	transaction := &Transaction{}
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

	// read output counts
	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTransactionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	// get last four bytes for lock time
	lockTimeBytes := make([]byte, 4)
	io.ReadFull(bufReader, lockTimeBytes)
	transaction.lockTime = LittleEndianToBigInt(lockTimeBytes, LITTLE_ENDIAN_4_BYTES)

	return transaction
}

// parseSegwit parses a SegWit (BIP141) Bitcoin transaction from the reader.
func parseSegwit(bufReader *bufio.Reader) *Transaction {
	transaction := &Transaction{}
	transaction.segwit = true

	verBuf := make([]byte, 4)
	io.ReadFull(bufReader, verBuf)
	version := LittleEndianToBigInt(verBuf, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("transaction version:%x\n", version)
	transaction.version = version

	// check the following 2 bytes
	marker := make([]byte, 2)
	io.ReadFull(bufReader, marker)
	if marker[0] != 0x00 && marker[1] != 0x01 {
		panic("Not segwit transaction")
	}

	inputs := getInputCount(bufReader)
	transactionInputs := []*TransactionInput{}
	for i := 0; i < int(inputs.Int64()); i++ {
		input := NewTransactionInput(bufReader)
		transactionInputs = append(transactionInputs, input)
	}
	transaction.txInputs = transactionInputs

	// read output counts
	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTransactionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	// parsing witness data,
	for _, input := range transactionInputs {
		numItems := ReadVarint(bufReader)
		items := make([][]byte, 0)
		for i := 0; i < int(numItems.Int64()); i++ {
			itemLen := ReadVarint(bufReader)
			if itemLen.Int64() == 0 {
				items = append(items, []byte{})
			} else {
				item := make([]byte, itemLen.Int64())
				io.ReadFull(bufReader, item)
				items = append(items, item)
			}
		}
		input.witness = items
	}

	// get last four bytes for lock time
	lockTimeBytes := make([]byte, 4)
	io.ReadFull(bufReader, lockTimeBytes)
	transaction.lockTime = LittleEndianToBigInt(lockTimeBytes, LITTLE_ENDIAN_4_BYTES)

	return transaction
}
