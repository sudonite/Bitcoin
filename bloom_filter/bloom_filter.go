package bloomfilter

import (
	"fmt"
	"math/big"

	"github.com/spaolacci/murmur3"
	"github.com/sudonite/bitcoin/transaction"
)

const (
	BIP37_CONSTANT = 0xfba4c795
)

// BloomFilter represents a BIP37-style bloom filter
type BloomFilter struct {
	size      uint64
	buckets   []byte
	funcCount uint64
	tweak     uint64
}

// FilteredDataType returns the payload type for filterload messages
func FilteredDataType() []byte {
	return []byte{0x00, 0x00, 0x00, 0x03}
}

// NewBloomFilter creates a new empty bloom filter
func NewBloomFilter(size uint64, funcCount uint64, tweak uint64) *BloomFilter {
	return &BloomFilter{
		size:      size,
		funcCount: funcCount,
		buckets:   make([]byte, size*8),
		tweak:     tweak,
	}
}

// Add inserts an item (byte array) into the bloom filter
func (b *BloomFilter) Add(item []byte) {
	for i := 0; i < int(b.funcCount); i++ {
		seed := uint32(uint64(i*BIP37_CONSTANT) + b.tweak)
		h := murmur3.Sum32WithSeed(item, seed)
		idx := h % uint32(len(b.buckets))
		b.buckets[idx] = 1
		fmt.Printf("idx to 1: %d\n", idx)
	}

	// debug set all buckets to 1
	for i := 0; i < len(b.buckets)/4; i++ {
		b.buckets[i] = 1
	}
}

// FilterLoadMessage represents the "filterload" network message
type FilterLoadMessage struct {
	payload []byte
}

// Command returns the network command name
func (f *FilterLoadMessage) Command() string {
	return "filterload"
}

// Serialize returns the raw payload bytes for the message
func (f *FilterLoadMessage) Serialize() []byte {
	return f.payload
}

// BitsToBytes converts the bloom filter's bit array into a byte array
func (b *BloomFilter) BitsToBytes() []byte {
	if len(b.buckets)%8 != 0 {
		panic("length of buckets should divide over 8")
	}

	result := make([]byte, len(b.buckets)/8)
	for i, bit := range b.buckets {
		byteIndex := i / 8
		bitIndex := i % 8
		if bit == 1 {
			result[byteIndex] |= 1 << bitIndex
		}
	}

	return result
}

// FilterLoadMsg generates a FilterLoadMessage from the bloom filter
func (b *BloomFilter) FilterLoadMsg() *FilterLoadMessage {
	payload := make([]byte, 0)
	size := big.NewInt(int64(b.size))
	payload = append(payload, transaction.EncodeVarint(size)...)
	payload = append(payload, b.BitsToBytes()...)
	funcCount := big.NewInt(int64(b.funcCount))
	payload = append(payload, transaction.BigIntToLittleEndian(funcCount, transaction.LITTLE_ENDIAN_4_BYTES)...)
	tweak := big.NewInt(int64(b.tweak))
	payload = append(payload, transaction.BigIntToLittleEndian(tweak, transaction.LITTLE_ENDIAN_4_BYTES)...)
	// include all transaction that have collision
	payload = append(payload, 0x01)
	return &FilterLoadMessage{
		payload: payload,
	}
}
