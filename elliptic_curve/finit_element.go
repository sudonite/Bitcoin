package elliptic_curve

import (
	"fmt"
	"math/big"
)

// Represents an element of a finite field
type FieldElement struct {
	order *big.Int // field order
	num   *big.Int // value of the given element in the field
}

// Creates a field element in the secp256k1 prime field (p = 2^256 - 2^32 - 977)
func S256Field(num *big.Int) *FieldElement {
	twoExp256 := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	twoExp32 := new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	p := new(big.Int).Sub(new(big.Int).Sub(twoExp256, twoExp32), big.NewInt(977))
	return NewFieldElement(p, num)
}

// Init function for FieldElement
func NewFieldElement(order *big.Int, num *big.Int) *FieldElement {
	if order.Cmp(num) == -1 {
		err := fmt.Sprintf("Num not in the range of 0 to %d\n", order)
		panic(err)
	}

	return &FieldElement{
		order: order,
		num:   num,
	}
}

// String representation of FieldElement
func (f *FieldElement) String() string {
	return fmt.Sprintf("FieldElement{order: %x, num: %x}", f.order, f.num)
}

// Checks equality of two field elements
func (f *FieldElement) EqualTo(other *FieldElement) bool {
	return f.order.Cmp(other.order) == 0 && f.num.Cmp(other.num) == 0
}

// Adds two field elements
func (f *FieldElement) Add(other *FieldElement) *FieldElement {
	f.checkOrder(other)
	var op big.Int
	return NewFieldElement(f.order, op.Mod(op.Add(f.num, other.num), f.order))
}

// Returns additive inverse
func (f *FieldElement) Negate() *FieldElement {
	var op big.Int
	return NewFieldElement(f.order, op.Sub(f.order, f.num))
}

// Subtracts two field elements
func (f *FieldElement) Subtract(other *FieldElement) *FieldElement {
	return f.Add(other.Negate())
}

// Multiplies two field elements
func (f *FieldElement) Multiply(other *FieldElement) *FieldElement {
	f.checkOrder(other)
	var op big.Int
	mul := op.Mul(f.num, other.num)
	return NewFieldElement(f.order, op.Mod(mul, f.order))
}

// Raises the field element to a given power
func (f *FieldElement) Power(power *big.Int) *FieldElement {
	var op big.Int
	t := op.Mod(power, op.Sub(f.order, big.NewInt(1)))
	powerRes := op.Exp(f.num, t, f.order)
	return NewFieldElement(f.order, powerRes)
}

// Multiplies field element by a scalar
func (f *FieldElement) ScalarMul(val *big.Int) *FieldElement {
	var op big.Int
	res := op.Mul(f.num, val)
	res = op.Mod(res, f.order)
	return NewFieldElement(f.order, res)
}

// Divides two field elements using modular inverse
func (f *FieldElement) Divide(other *FieldElement) *FieldElement {
	f.checkOrder(other)
	var op big.Int
	otherReverse := other.Power(op.Sub(f.order, big.NewInt(int64(2))))
	return f.Multiply(otherReverse)
}

// Returns the multiplicative inverse using Fermat's little theorem (a^(p-2) mod p)
func (f *FieldElement) Inverse() *FieldElement {
	var op big.Int
	return f.Power(op.Sub(f.order, big.NewInt(int64(2))))
}

// Computes the square root of the field element
func (f *FieldElement) Sqrt() *FieldElement {
	orderAddOne := new(big.Int).Add(f.order, big.NewInt(1))
	modRes := new(big.Int).Mod(orderAddOne, big.NewInt(4))

	if modRes.Cmp(big.NewInt(0)) != 0 {
		panic("order plus one mod 4 is not 0")
	}

	return f.Power(new(big.Int).Div(orderAddOne, big.NewInt(4)))
}

// Checks if elements are from the same field
func (f *FieldElement) checkOrder(other *FieldElement) {
	if f.order.Cmp(other.order) != 0 {
		panic("add need to do on the field element with the same order")
	}
}
