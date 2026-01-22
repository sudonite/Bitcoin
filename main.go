package main

import (
	"fmt"

	bloomfilter "github.com/sudonite/bitcoin/bloom_filter"
)

func main() {
	//testing add of bloom filter
	bf := bloomfilter.NewBloomFilter(10, 5, 99)
	bf.Add([]byte("Hello World"))
	fmt.Printf("%x\n", bf.BitsToBytes())

	bf.Add([]byte("Goodbye!"))
	fmt.Printf("%x\n", bf.BitsToBytes())

	//testing filterload
	fmt.Printf("%x\n", bf.FilterLoadMsg().Serialize())
}
