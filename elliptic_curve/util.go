package elliptic_curve

import (
	"crypto/sha256"
	"math/big"

	"github.com/tsuna/endian"
	"golang.org/x/crypto/ripemd160"
)

// Performs SHA256(SHA256(text)) hashing
func Hash256(text string) []byte {
	hashOnce := sha256.Sum256([]byte(text))
	hashTwice := sha256.Sum256(hashOnce[:])
	return hashTwice[:]
}

// Returns the secp256k1 generator point G
func GetGenerator() *Point {
	Gx := new(big.Int)
	Gx.SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)

	Gy := new(big.Int)
	Gy.SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

	return S256Point(Gx, Gy)
}

// Returns the secp256k1 curve order n (group size used in Bitcoin)
func GetBitcoinValueN() *big.Int {
	n := new(big.Int)
	n.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	return n
}

// Parses a SEC serialized point (compressed or uncompressed)
func ParseSEC(secBin []byte) *Point {
	if secBin[0] == 4 {
		x := new(big.Int).SetBytes(secBin[1:33])
		y := new(big.Int).SetBytes(secBin[33:65])
		return S256Point(x, y)
	}

	x := new(big.Int).SetBytes(secBin[1:])
	y := S256Field(x).Power(big.NewInt(3)).Add(S256Field(big.NewInt(7))).Sqrt()

	var yEven *FieldElement
	var yOdd *FieldElement

	if new(big.Int).Mod(y.num, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		yEven = y
		yOdd = y.Negate()
	} else {
		yEven = y.Negate()
		yOdd = y
	}

	if secBin[0] == 2 {
		return S256Point(x, yEven.num)
	}

	return S256Point(x, yOdd.num)
}

// Encodes a byte slice into a Bitcoin-style Base58 string
func EncodeBase58(s []byte) string {
	BASE58_ALPHABET := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	count := 0
	for idx := range s {
		if s[idx] == 0 {
			count++
		} else {
			break
		}
	}

	prefix := ""
	for i := 0; i < count; i++ {
		prefix += "1"
	}

	result := ""
	num := new(big.Int).SetBytes(s)
	for num.Cmp(big.NewInt(0)) > 0 {
		var divOp, modOp big.Int
		mod := modOp.Mod(num, big.NewInt(58))
		num = divOp.Div(num, big.NewInt(58))
		result = string(BASE58_ALPHABET[mod.Int64()]) + result
	}

	return prefix + result
}

// Computes Base58Check encoding: payload + first 4 bytes of double SHA256 checksum
func Base58Checksum(s []byte) string {
	hash256 := Hash256(string(s))
	return EncodeBase58(append(s, hash256[:4]...))
}

// Computes HASH160 = RIPEMD160(SHA256(input))s
func Hash160(s []byte) []byte {
	sha256 := sha256.Sum256(s)
	hasher := ripemd160.New()
	hasher.Write(sha256[:])
	hashBytes := hasher.Sum(nil)

	return hashBytes
}

type LITTLE_ENDIAN_LENGTH int

// Byte length selector for little-endian big-int serialization
const (
	LITTLE_ENDIAN_2_BYTES = iota
	LITTLE_ENDIAN_4_BYTES
	LITTLE_ENDIAN_8_BYTES
)

// Serializes big.Int into little-endian bytes with fixed length
func BigIntToLittleEndian(v *big.Int, length LITTLE_ENDIAN_LENGTH) []byte {
	switch length {
	case LITTLE_ENDIAN_2_BYTES:
		val := v.Int64()
		littleEndianVal := endian.HostToNetUint16(uint16(val))
		p := big.NewInt(int64(littleEndianVal))
		return p.Bytes()
	case LITTLE_ENDIAN_4_BYTES:
		val := v.Int64()
		littleEndianVal := endian.HostToNetUint32(uint32(val))
		p := big.NewInt(int64(littleEndianVal))
		return p.Bytes()
	case LITTLE_ENDIAN_8_BYTES:
		val := v.Int64()
		littleEndianVal := endian.HostToNetUint64(uint64(val))
		p := big.NewInt(int64(littleEndianVal))
		return p.Bytes()
	}

	return nil
}

// Parses little-endian bytes into big.Int assuming fixed length
func LittleEndianToBigInt(bytes []byte, length LITTLE_ENDIAN_LENGTH) *big.Int {
	switch length {
	case LITTLE_ENDIAN_2_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint16(uint16(p.Uint64()))
		return big.NewInt(int64(val))
	case LITTLE_ENDIAN_4_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint32(uint32(p.Uint64()))
		return big.NewInt(int64(val))
	case LITTLE_ENDIAN_8_BYTES:
		p := new(big.Int).SetBytes(bytes)
		val := endian.NetToHostUint64(uint64(p.Uint64()))
		return big.NewInt(int64(val))
	}

	return nil
}
