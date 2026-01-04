package elliptic_curve

import (
	"fmt"
	"math/big"
)

// Operation type for field arithmetic
type OP_TYPE int

const (
	ADD OP_TYPE = iota // Addition
	SUB                // Subtraction
	MUL                // Multiplication
	DIV                // Division
	EXP                // Exponentiation
)

// Represents a point on an elliptic curve
type Point struct {
	a *FieldElement // curve coefficient a
	b *FieldElement // curve coefficient b
	x *FieldElement // x-coordinate
	y *FieldElement // y-coordinate
}

// Performs a selected operation on field elements
func OpOnBig(x, y *FieldElement, scalar *big.Int, opType OP_TYPE) *FieldElement {
	switch opType {
	case ADD:
		return x.Add(y)
	case SUB:
		return x.Subtract(y)
	case MUL:
		if y != nil {
			return x.Multiply(y)
		}
		if scalar != nil {
			return x.ScalarMul(scalar)
		}
		panic("error in multiply")
	case DIV:
		return x.Divide(y)
	case EXP:
		if scalar == nil {
			panic("scalar should not be nil for EXP")
		}
		return x.Power(scalar)
	}

	panic("should not come to here")
}

// Creates a point on secp256k1 curve with a=0, b=7 (y^2 = x^3 + 7 mod p)
func S256Point(x, y *big.Int) *Point {
	a := S256Field(big.NewInt(0))
	b := S256Field(big.NewInt(7))

	if x == nil && y == nil {
		return &Point{
			x: nil,
			y: nil,
			a: a,
			b: b,
		}
	}

	return &Point{
		x: S256Field(x),
		y: S256Field(y),
		a: a,
		b: b,
	}
}

// Creates a new point and checks if it lies on the curve
func NewEllipticCurvePoint(x, y, a, b *FieldElement) *Point {
	if x == nil && y == nil {
		return &Point{
			x: x,
			y: y,
			a: a,
			b: b,
		}
	}

	// Verify curve equation: y^2 = x^3 + ax + b
	left := OpOnBig(y, nil, big.NewInt(2), EXP)
	x3 := OpOnBig(x, nil, big.NewInt(3), EXP)
	ax := OpOnBig(a, x, nil, MUL)
	right := OpOnBig(OpOnBig(x3, ax, nil, ADD), b, nil, ADD)

	if !left.EqualTo(right) {
		err := fmt.Sprintf(
			"Point(%v, %v) is not on the curve with a:%v, b:%v\n",
			x, y, a, b,
		)
		panic(err)
	}

	return &Point{
		x: x,
		y: y,
		a: a,
		b: b,
	}
}

// Returns string representation of a point
func (p *Point) String() string {
	xString := "nil"
	yString := "nil"

	if p.x != nil {
		xString = p.x.String()
	}
	if p.y != nil {
		yString = p.y.String()
	}
	return fmt.Sprintf("(x:%s, y:%s, a:%s, b:%s)", xString, yString, p.a.String(), p.b.String())
}

// Multiplies a point by a scalar using double-and-add
func (p *Point) ScalarMul(scalar *big.Int) *Point {
	if scalar == nil {
		panic("scalar can't be nil")
	}

	result := NewEllipticCurvePoint(nil, nil, p.a, p.b)

	for i := scalar.BitLen() - 1; i >= 0; i-- {
		result = result.Add(result)

		if scalar.Bit(i) == 1 {
			result = result.Add(p)
		}
	}

	return result
}

// Adds two points on the same elliptic curve
func (p *Point) Add(other *Point) *Point {
	// Ensure both points are on the same curve
	if !p.a.EqualTo(other.a) || !p.b.EqualTo(other.b) {
		panic("given two point are not on the same curve")
	}

	if p.x == nil {
		return other
	}
	if other.x == nil {
		return p
	}

	zero := NewFieldElement(p.x.order, big.NewInt(0))

	if p.x.EqualTo(other.x) && OpOnBig(p.y, other.y, nil, ADD).EqualTo(zero) {
		return &Point{
			x: nil,
			y: nil,
			a: p.a,
			b: p.b,
		}
	}

	var numerator *FieldElement
	var denominator *FieldElement

	if p.x.EqualTo(other.x) && p.y.EqualTo(other.y) {
		xSqrt := OpOnBig(p.x, nil, big.NewInt(2), EXP)
		threeXQsrt := OpOnBig(xSqrt, nil, big.NewInt(3), MUL)
		numerator = OpOnBig(threeXQsrt, p.a, nil, ADD)
		denominator = OpOnBig(p.y, nil, big.NewInt(2), MUL)
	} else {
		numerator = OpOnBig(other.y, p.y, nil, SUB)
		denominator = OpOnBig(other.x, p.x, nil, SUB)
	}

	// Compute slope
	slope := OpOnBig(numerator, denominator, nil, DIV)
	slopeSqrt := OpOnBig(slope, nil, big.NewInt(2), EXP)

	x3 := OpOnBig(OpOnBig(slopeSqrt, p.x, nil, SUB), other.x, nil, SUB)
	x3Minusx1 := OpOnBig(x3, p.x, nil, SUB)

	y3 := OpOnBig(OpOnBig(slope, x3Minusx1, nil, MUL), p.y, nil, ADD)
	minusY3 := OpOnBig(y3, nil, big.NewInt(-1), MUL)

	return &Point{
		x: x3,
		y: minusY3,
		a: p.a,
		b: p.b,
	}
}

// Checks if two points are equal
func (p *Point) Equal(other *Point) bool {
	return p.a.EqualTo(other.a) &&
		p.b.EqualTo(other.b) &&
		p.x.EqualTo(other.x) &&
		p.y.EqualTo(other.y)
}

// Checks if two points are not equal
func (p *Point) NotEqual(other *Point) bool {
	return !p.a.EqualTo(other.a) ||
		!p.b.EqualTo(other.b) ||
		!p.x.EqualTo(other.x) ||
		!p.y.EqualTo(other.y)
}

// Verifies an ECDSA signature
func (p *Point) Verify(z *FieldElement, sig *Signature) bool {
	sInverse := sig.s.Inverse()
	u := z.Multiply(sInverse)
	v := sig.r.Multiply(sInverse)
	G := GetGenerator()
	total := (G.ScalarMul(u.num)).Add(p.ScalarMul(v.num))
	return total.x.num.Cmp(sig.r.num) == 0
}

// Returns the SEC (Standards for Efficient Cryptography) uncompressed serialization of the point
func (p *Point) Sec(compressed bool) (string, []byte) {
	secBytes := []byte{}

	if !compressed {
		secBytes = append(secBytes, 0x04)
		secBytes = append(secBytes, p.x.num.Bytes()...)
		secBytes = append(secBytes, p.y.num.Bytes()...)
		return fmt.Sprintf("04%064x%064x", p.x.num, p.y.num), secBytes
	}

	if new(big.Int).Mod(p.y.num, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		secBytes = append(secBytes, 0x02)
		secBytes = append(secBytes, p.x.num.Bytes()...)
		return fmt.Sprintf("02%064x", p.x.num), secBytes
	} else {
		secBytes = append(secBytes, 0x03)
		secBytes = append(secBytes, p.x.num.Bytes()...)
		return fmt.Sprintf("03%064x", p.x.num), secBytes
	}
}

func (p *Point) Address(compressed bool, testnet bool) string {
	hash160 := p.hash160(compressed)
	prefix := []byte{}
	if testnet {
		prefix = append(prefix, 0x6f)
	} else {
		prefix = append(prefix, 0x00)
	}

	return Base58Checksum(append(prefix, hash160...))
}

func (p *Point) hash160(compressed bool) []byte {
	_, secBytes := p.Sec(compressed)
	return Hash160(secBytes)
}
