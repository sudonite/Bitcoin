package main

import (
	"encoding/hex"
	"fmt"

	tx "github.com/sudonite/bitcoin/transaction"
)

func main() {
	lastBlockRawData, err := hex.DecodeString("00000020fdf740b0e49cf75bb3d5168fb3586f7613dcc5cd89675b0100000000000000002e37b144c0baced07eb7e7b64da916cd3121f2427005551aeb0ec6a6402ac7d7f0e4235954d801187f5da9f5")
	if err != nil {
		panic(err)
	}
	firstBlockRawData, err := hex.DecodeString("000000201ecd89664fd205a37566e694269ed76e425803003628ab010000000000000000bfcade29d080d9aae8fd461254b041805ae442749f2a40100440fc0e3d5868e55019345954d80118a1721b2e")
	if err != nil {
		panic(err)
	}

	newTarget := tx.ComputeNewTarget(firstBlockRawData, lastBlockRawData)
	fmt.Printf("new target: %064x\n", newTarget.Bytes())

	newBits := tx.TargetToBits(newTarget)
	fmt.Printf("new bits:%x\n", newBits)
}
