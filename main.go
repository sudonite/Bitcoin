package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
	tx "github.com/sudonite/bitcoin/transaction"
)

func main() {
	p := new(big.Int)
	h256 := ecc.Hash256("secret")
	fmt.Printf("h256: %x\n", h256)
	p.SetBytes(tx.ReverseByteSlice(h256))
	fmt.Printf("p is %x\n", p)
	privateKey := ecc.NewPrivateKey(p)
	pubKey := privateKey.GetPublicKey()

	prevTxHash, err := hex.DecodeString("703158ce66391f094ab2195cfe5579214073ba90997d0b98e6e410ed1b67aa8a")
	if err != nil {
		panic(err)
	}
	prevTxIndex := big.NewInt(int64(1))
	txInput := tx.InitTransactionInput(prevTxHash, prevTxIndex)

	/*
		0.00019756 btc
		send back 0.0001 to myself, and set 0.00009756 as fee to miners
	*/
	changeAmount := big.NewInt(int64(0.0001 * tx.STASHI_PER_BITCOIN))
	changeH160 := ecc.DecodeBase58("mpNzUycBH6SDU9amLK5raP6Qm71CWNezHv")
	changeScript := tx.P2pkScript(changeH160)
	changeOut := tx.InitTransactionOutput(changeAmount, changeScript)

	transaction := tx.InitTransaction(big.NewInt(int64(1)), []*tx.TransactionInput{txInput},
		[]*tx.TransactionOutput{changeOut}, big.NewInt(int64(0)), true)

	fmt.Printf("%s\n", transaction)

	//sign the first transaction
	z := transaction.SignHash(0)
	zMsg := new(big.Int)
	zMsg.SetBytes(z)
	der := privateKey.Sign(zMsg).Der()
	//add the last byte as hash type
	sig := append(der, byte(tx.SIGHASH_ALL))
	_, sec := pubKey.Sec(true)
	scriptSig := tx.InitScriptSig([][]byte{sig, sec})
	txInput.SetScriptSig(scriptSig)

	rawTx := transaction.SerializeWithSign(-1)
	fmt.Printf("raw tx: %x\n", rawTx)
}
