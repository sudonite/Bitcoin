package transaction

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

const (
	OP_0 = 0
)

const (
	OP_1NEGATE = iota + 79
)

const (
	OP_1 = iota + 81
	OP_2
	OP_3
	OP_4
	OP_5
	OP_6
	OP_7
	OP_8
	OP_9
	OP_10
	OP_11
	OP_12
	OP_13
	OP_14
	OP_15
	OP_16
	OP_NOP
)

const (
	OP_IF = iota + 99
	OP_NOTIf
)

const (
	OP_VERIFY = iota + 105
	OP_RETURN
	OP_TOTALSTACK
	OP_FROMALTSTACK
	OP_2DROP
	OP_2DUP
	OP_3DUP
	OP_2OVER
	OP_2ROT
	OP_2SWAP
	OP_IFDUP
	OP_DEPTH
	OP_DROP
	OP_DUP
	OP_NIP
	OP_OVER
	OP_PICK
	OP_ROLL
	OP_ROT
	OP_SWAP
	OP_TUCK
)

const (
	OP_SIZE = iota + 130
)

const (
	OP_EQUAL = iota + 135
	OP_EQUALVERIFY
)

const (
	OP_1ADD = iota + 139
	OP_1SUB
)

const (
	OP_NEGATE = iota + 143
	OP_ABS
	OP_NOT
	OP_0NOTEQUAL
	OP_ADD
	OP_SUB
	OP_MUL
)

const (
	OP_BOOLAND = iota + 154
	OP_BOOLOR
	OP_NUMEQUAL
	OP_NUMEQUALVERIFY
	OP_NUMNOTEQUAL
	OP_LESSTHAN
	OP_GREATERTHAN
	OP_LESSTHANOREQUAL
	OP_GREATERTHANOREQUAL
	OP_MIN
	OP_MAX
	OP_WITHIN
	OP_RIPEMD160
	OP_SHA1
	OP_SHA256
	OP_HASH160
	OP_HASH256
)

const (
	OP_CHECKSIG = iota + 172
	OP_HECKSIGVERIFY
	OP_CHECKMULTISIG
	OP_CHECKMULTISIGVERIFY
	OP_NOP1
	OP_CHECKLOGTIMEVERIFY
	OP_CHECKSEQUENCEVERIFY
	OP_NOP4
	OP_NOP5
	OP_NOP6
	OP_NOP7
	OP_NOP8
	OP_NOP9
	OP_NOP10
)

const (
	OP_P2SH = 254
)

// BitcoinOpCode handles Bitcoin Script execution.
type BitcoinOpCode struct {
	opCodeNames map[int]string
	stack       [][]byte
	altStack    [][]byte
	cmds        [][]byte
	witness     [][]byte
}

// Creates a new BitcoinOpCode instance with opcode names initialized.
func NewBitcoinOpCode() *BitcoinOpCode {
	opCodeNames := map[int]string{
		0:   "OP_0",
		76:  "OP_PUSHDATA1",
		77:  "OP_PUSHDATA2",
		78:  "OP_PUSHDATA4",
		79:  "OP_1NEGATE",
		81:  "OP_1",
		82:  "OP_2",
		83:  "OP_3",
		84:  "OP_4",
		85:  "OP_5",
		86:  "OP_6",
		87:  "OP_7",
		88:  "OP_8",
		89:  "OP_9",
		90:  "OP_10",
		91:  "OP_11",
		92:  "OP_12",
		93:  "OP_13",
		94:  "OP_14",
		95:  "OP_15",
		96:  "OP_16",
		97:  "OP_NOP",
		99:  "OP_IF",
		100: "OP_NOTIF",
		103: "OP_ELSE",
		104: "OP_ENDIF",
		105: "OP_VERIFY",
		106: "OP_RETURN",
		107: "OP_TOALTSTACK",
		108: "OP_FROMALTSTACK",
		109: "OP_2DROP",
		110: "OP_2DUP",
		111: "OP_3DUP",
		112: "OP_2OVER",
		113: "OP_2ROT",
		114: "OP_2SWAP",
		115: "OP_IFDUP",
		116: "OP_DEPTH",
		117: "OP_DROP",
		118: "OP_DUP",
		119: "OP_NIP",
		120: "OP_OVER",
		121: "OP_PICK",
		122: "OP_ROLL",
		123: "OP_ROT",
		124: "OP_SWAP",
		125: "OP_TUCK",
		130: "OP_SIZE",
		135: "OP_EQUAL",
		136: "OP_EQUALVERIFY",
		139: "OP_1ADD",
		140: "OP_1SUB",
		143: "OP_NEGATE",
		144: "OP_ABS",
		145: "OP_NOT",
		146: "OP_0NOTEQUAL",
		147: "OP_ADD",
		148: "OP_SUB",
		149: "OP_MUL",
		154: "OP_BOOLAND",
		155: "OP_BOOLOR",
		156: "OP_NUMEQUAL",
		157: "OP_NUMEQUALVERIFY",
		158: "OP_NUMNOTEQUAL",
		159: "OP_LESSTHAN",
		160: "OP_GREATERTHAN",
		161: "OP_LESSTHANOREQUAL",
		162: "OP_GREATERTHANOREQUAL",
		163: "OP_MIN",
		164: "OP_MAX",
		165: "OP_WITHIN",
		166: "OP_RIPEMD160",
		167: "OP_SHA1",
		168: "OP_SHA256",
		169: "OP_HASH160",
		170: "OP_HASH256",
		171: "OP_CODESEPARATOR",
		172: "OP_CHECKSIG",
		173: "OP_CHECKSIGVERIFY",
		174: "OP_CHECKMULTISIG",
		175: "OP_CHECKMULTISIGVERIFY",
		176: "OP_NOP1",
		177: "OP_CHECKLOCKTIMEVERIFY",
		178: "OP_CHECKSEQUENCEVERIFY",
		179: "OP_NOP4",
		180: "OP_NOP5",
		181: "OP_NOP6",
		182: "OP_NOP7",
		183: "OP_NOP8",
		184: "OP_NOP9",
		185: "OP_NOP10",
		254: "OP_P2SH",
	}
	return &BitcoinOpCode{
		opCodeNames: opCodeNames,
		stack:       make([][]byte, 0),
		altStack:    make([][]byte, 0),
		cmds:        make([][]byte, 0),
	}
}

// Executes a single Bitcoin Script operations
func (b *BitcoinOpCode) ExecuteOperation(cmd int, z []byte) bool {
	switch cmd {
	case OP_CHECKSIG:
		return b.opCheckSig(z)
	case OP_DUP:
		return b.opDup()
	case OP_HASH160:
		return b.opHash160()
	case OP_EQUALVERIFY:
		return b.opEqualVerify()
	case OP_CHECKMULTISIG:
		return b.opCheckMultiSig(z)
	case OP_P2SH:
		return b.opP2sh()
	case OP_0:
		fallthrough
	case OP_1:
		fallthrough
	case OP_2:
		fallthrough
	case OP_3:
		fallthrough
	case OP_4:
		fallthrough
	case OP_5:
		fallthrough
	case OP_6:
		fallthrough
	case OP_7:
		fallthrough
	case OP_8:
		fallthrough
	case OP_9:
		fallthrough
	case OP_10:
		fallthrough
	case OP_11:
		fallthrough
	case OP_12:
		fallthrough
	case OP_13:
		fallthrough
	case OP_14:
		fallthrough
	case OP_15:
		fallthrough
	case OP_16:
		return b.opNum(byte(cmd))
	case OP_EQUAL:
		return b.opEqual()
	default:
		errStr := fmt.Sprintf("operation %s not implemented\n", b.opCodeNames[cmd])
		panic(errStr)
	}
}

// Remove command from the stack
func (b *BitcoinOpCode) RemoveCmd() []byte {
	cmd := b.cmds[0]
	b.cmds = b.cmds[1:]
	return cmd
}

// Checking the stack has any command
func (b *BitcoinOpCode) HasCmd() bool {
	return len(b.cmds) > 0
}

// Append element to the stack
func (b *BitcoinOpCode) AppendDataElement(element []byte) {
	b.stack = append(b.stack, element)

	if b.isP2sh() {
		b.cmds = append([][]byte{{OP_P2SH}}, b.cmds...)
	}
}

// Encode integers to Bitcoin Script format
func (b *BitcoinOpCode) EncodeNum(num int64) []byte {
	if num == 0 {
		return []byte("")
	}

	result := []byte{}
	absNum := num
	negative := false
	if num < 0 {
		absNum = -num
		negative = true
	}

	for absNum > 0 {
		result = append(result, byte(absNum&0xff))
		absNum >>= 8
	}

	if (result[len(result)-1] & 0x80) != 0 {
		if negative {
			result = append(result, 0x80)
		} else {
			result = append(result, 0x00)
		}
	} else if negative {
		result[len(result)-1] |= 0x80
	}

	return result
}

// Decode integers from Bitcoin Script format
func (b *BitcoinOpCode) DecodeNum(element []byte) int64 {
	if len(element) == 0 {
		return 0
	}
	bigEndian := ReverseByteSlice(element)
	negative := false
	result := int64(0)

	if (bigEndian[0] & 0x80) != 0 {
		negative = true
		result = int64(bigEndian[0] & 0x7f)
	} else {
		negative = false
		result = int64(bigEndian[0])
	}

	for i := 1; i < len(bigEndian); i++ {
		result <<= 8
		result += int64(bigEndian[i])
	}

	if negative {
		return -result
	}

	return result
}

// Pushes the numeric value represented by OP_1–OP_16 onto the stack
func (b *BitcoinOpCode) opNum(op byte) bool {
	opNum := byte(0)
	if op >= OP_1 && op <= OP_16 {
		opNum = (op - OP_1) + 1
	}
	b.stack = append(b.stack, b.EncodeNum(int64(opNum)))
	return true
}

// Duplicate Script operation implementation
func (b *BitcoinOpCode) opDup() bool {
	if len(b.stack) < 1 {
		return false
	}

	b.stack = append(b.stack, b.stack[len(b.stack)-1])
	return true
}

// Hash160 Script operation implementation
func (b *BitcoinOpCode) opHash160() bool {
	if len(b.stack) < 1 {
		return false
	}

	element := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	hash160 := ecc.Hash160(element)
	b.stack = append(b.stack, hash160)
	return true
}

// Equal Script operation implementation
func (b *BitcoinOpCode) opEqual() bool {
	if len(b.stack) < 2 {
		return false
	}

	elem1 := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	elem2 := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	if bytes.Equal(elem1, elem2) {
		b.stack = append(b.stack, b.EncodeNum(1))
	} else {
		b.stack = append(b.stack, b.EncodeNum(0))
	}
	return true
}

// Verify Script operation implementation
func (b *BitcoinOpCode) opVerify() bool {
	if len(b.stack) < 1 {
		return false
	}

	elem := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	if b.DecodeNum(elem) == 0 {
		return false
	}

	return true
}

// Equal and Verify Script operation implementation
func (b *BitcoinOpCode) opEqualVerify() bool {
	resEqual := b.opEqual()
	resVerify := b.opVerify()
	return resEqual && resVerify
}

// Pops and returns the top element from the stack
func (b *BitcoinOpCode) popStack() []byte {
	elem := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	return elem
}

// Implements OP_CHECKMULTISIG by verifying multiple signatures against a set of public keys
func (b *BitcoinOpCode) opCheckMultiSig(zBin []byte) bool {
	if len(b.stack) < 1 {
		return false
	}
	// read the top element to get the number of public keys
	pubKeyCounts := int(b.DecodeNum(b.popStack()))
	if len(b.stack) < pubKeyCounts+1 {
		return false
	}

	secPubKeys := make([][]byte, 0)
	for i := 0; i < pubKeyCounts; i++ {
		secPubKeys = append(secPubKeys, b.popStack())
	}

	// get the number of signatures
	sigCounts := int(b.DecodeNum(b.popStack()))
	if len(b.stack) < sigCounts+1 {
		return false
	}

	derSignatures := make([][]byte, 0)
	for i := 0; i < sigCounts; i++ {
		signature := b.popStack()
		// remove last byte, it is hash type
		signature = signature[0 : len(signature)-1]
		derSignatures = append(derSignatures, signature)
	}

	points := make([]*ecc.Point, 0)
	sigs := make([]*ecc.Signature, 0)
	for i := 0; i < pubKeyCounts; i++ {
		points = append(points, ecc.ParseSEC(secPubKeys[i]))
	}
	for i := 0; i < sigCounts; i++ {
		sigs = append(sigs, ecc.ParseSigBin(derSignatures[i]))
	}

	z := new(big.Int)
	z.SetBytes(zBin)
	n := ecc.GetBitcoinValueN()
	zField := ecc.NewFieldElement(n, z)

	for _, sig := range sigs {
		if len(points) == 0 {
			return false
		}
		for len(points) > 0 {
			point := points[0]
			points = points[1:]
			if point.Verify(zField, sig) {
				break
			}
		}
	}
	b.stack = append(b.stack, b.EncodeNum(1))
	return true
}

// CheckSignature Script operation implementation
func (b *BitcoinOpCode) opCheckSig(zBin []byte) bool {
	if len(b.stack) < 2 {
		return false
	}

	pubKey := b.stack[len(b.stack)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	derSig := b.stack[len(b.stack)-1]
	derSig = derSig[0 : len(derSig)-1]
	b.stack = b.stack[0 : len(b.stack)-1]
	point := ecc.ParseSEC(pubKey)
	sig := ecc.ParseSigBin(derSig)

	z := new(big.Int)
	z.SetBytes(zBin)
	n := ecc.GetBitcoinValueN()
	zField := ecc.NewFieldElement(n, z)

	if point.Verify(zField, sig) == true {
		b.stack = append(b.stack, b.EncodeNum(1))
	} else {
		b.stack = append(b.stack, b.EncodeNum(0))
	}

	return true
}

// Executes a P2SH script by validating the redeem script hash and then running the redeem script
func (b *BitcoinOpCode) opP2sh() bool {
	// the first command is OP_HASH160
	b.RemoveCmd()
	// the second element is a data chunk of hash
	h160 := b.RemoveCmd()
	// the third element is OP_EQUAL
	b.RemoveCmd()

	redeemScriptBinary := b.stack[len(b.stack)-1]
	if b.opHash160() != true {
		return false
	}
	// append the hash160 above onto the stack
	b.stack = append(b.stack, h160)
	// compare the two 160 hash on the stack
	if b.opEqual() != true {
		return false
	}

	if b.opVerify() != true {
		// if the two hash are equal, value 1 will push on the stack
		return false
	}

	// parse the redeemscript and append its command for handling
	scriptReader := bytes.NewReader(redeemScriptBinary)
	redeemScriptSig := NewScriptSig(bufio.NewReader(scriptReader))
	b.cmds = append(b.cmds, redeemScriptSig.cmds...)
	return true
}

// Checks whether the remaining commands match the standard P2SH script pattern (OP_HASH160 <hash> OP_EQUAL)
func (b *BitcoinOpCode) isP2sh() bool {
	if len(b.cmds[0]) != 1 && b.cmds[0][0] != OP_HASH160 {
		return false
	}

	if len(b.cmds[1]) == 1 {
		return false
	}

	if len(b.cmds[2]) != 1 && b.cmds[2][0] != OP_EQUAL {
		return false
	}

	return true
}

// handleP2wpkh detects and expands a P2WPKH script into equivalent P2PKH commands for execution
func (b *BitcoinOpCode) handleP2wpkh() {
	if len(b.cmds) == 2 && b.cmds[0][0] == OP_0 && len(b.cmds[1]) == 20 {
		b.RemoveCmd()
		// remove OP_0
		h160 := b.RemoveCmd()

		// set up signature and pubkey
		b.cmds = append(b.cmds, b.witness...)
		// set up p2pk verify command
		p2sh := P2pkScript(h160)
		b.cmds = append(b.cmds, p2sh.bitcoinOpCode.cmds...)
	}
}
