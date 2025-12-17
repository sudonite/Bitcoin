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
	return fmt.Sprintf("FieldElement{order: %s, num: %s}", f.order.String(), f.num.String())
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
	powerRes := op.Exp(f.num, t, nil)
	modRes := op.Mod(powerRes, f.order)
	return NewFieldElement(f.order, modRes)
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

// Checks if elements are from the same field
func (f *FieldElement) checkOrder(other *FieldElement) {
	if f.order.Cmp(other.order) != 0 {
		panic("add need to do on the field element with the same order")
	}
}
