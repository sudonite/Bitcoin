package elliptic_curve

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type PrivateKey struct {
	secret *big.Int
	point  *Point
}

func NewPrivateKey(secret *big.Int) *PrivateKey {
	G := GetGenerator()

	return &PrivateKey{
		secret: secret,
		point:  G.ScalarMul(secret),
	}
}

func (p *PrivateKey) String() string {
	return fmt.Sprintf("Private key hex: {%s}", p.secret)
}

func (p *PrivateKey) GetPublicKey() *Point {
	return p.point
}

func (p *PrivateKey) Sign(z *big.Int) *Signature {
	G := GetGenerator()
	n := GetBitcoinValueN()

	k, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic(fmt.Sprintf("Sign err with rand int: %s", err))
	}
	r := G.ScalarMul(k).x.num

	kField := NewFieldElement(n, k)
	rField := NewFieldElement(n, r)
	eField := NewFieldElement(n, p.secret)
	zField := NewFieldElement(n, z)

	rMulSecret := rField.Multiply(eField)
	zAddMulSecret := zField.Add(rMulSecret)
	kInverse := kField.Inverse()

	sField := zAddMulSecret.Multiply(kInverse)

	var opDiv big.Int
	if sField.num.Cmp(opDiv.Div(n, big.NewInt(2))) > 0 {
		var opSub big.Int
		sField = NewFieldElement(n, opSub.Sub(n, sField.num))
	}

	return &Signature{
		r: NewFieldElement(n, r),
		s: sField,
	}
}
