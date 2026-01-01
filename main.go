package main

import (
	"fmt"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

func main() {
	/*
		twoExp256 := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
		twoExp32 := new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
		p := new(big.Int).Sub(new(big.Int).Sub(twoExp256, twoExp32), big.NewInt(977))
		fmt.Printf("p is %s\n", p)

		Gx := new(big.Int)
		Gx.SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
		fmt.Printf("Gx :%s\n", Gx)

		Gy := new(big.Int)
		Gy.SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
		fmt.Printf("Gy: %s\n", Gy)

		x1 := ecc.NewFieldElement(p, Gx)
		y1 := ecc.NewFieldElement(p, Gy)

		a := ecc.NewFieldElement(p, big.NewInt(0))
		b := ecc.NewFieldElement(p, big.NewInt(7))

		G := ecc.NewEllipticCurvePoint(x1, y1, a, b)
		fmt.Printf("G is on bitcoin elliptic curve with value is: %s\n", G)

		G = ecc.S256Point(Gx, Gy)
		n := new(big.Int)
		n.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

		fmt.Printf("n*G = %s\n", G.ScalarMul(n))
	*/

	/*
		n := new(big.Int)
		n.SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

		zVal := new(big.Int)
		zVal.SetString("bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423", 16)
		zField := elliptic_curve.NewFieldElement(n, zVal)

		rVal := new(big.Int)
		rVal.SetString("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16)
		rField := ecc.NewFieldElement(n, rVal)

		sVal := new(big.Int)
		sVal.SetString("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16)
		sField := ecc.NewFieldElement(n, sVal)

		//public key
		px := new(big.Int)
		px.SetString("4519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574", 16)
		py := new(big.Int)
		py.SetString("82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4", 16)
		point := ecc.S256Point(px, py)
		//	fmt.Printf("point is: %s\n", point)

		sig := ecc.NewSignature(rField, sField)
		verifyRes := point.Verify(zField, sig)
		fmt.Printf("verify result is %v\n", verifyRes)
	*/

	e := big.NewInt(12345)
	z := new(big.Int)
	z.SetBytes(ecc.Hash256("Testing my Signing"))

	privateKey := ecc.NewPrivateKey(e)
	sig := privateKey.Sign(z)
	fmt.Printf("sig is %s\n", sig)

	pubKey := privateKey.GetPublicKey()
	n := ecc.GetBitcoinValueN()
	zField := ecc.NewFieldElement(n, z)
	res := pubKey.Verify(zField, sig)
	fmt.Printf("Verify signature result: %v\n", res)
}
