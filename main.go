package main

import (
	"fmt"
	"math/big"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

func main() {
	p := ecc.NewEllipticCurvePoint(big.NewInt(-1), big.NewInt(-1), big.NewInt(5), big.NewInt(7))
	p2 := ecc.NewEllipticCurvePoint(big.NewInt(-1), big.NewInt(1), big.NewInt(5), big.NewInt(7))

	res := p.Add(p2)
	fmt.Printf("result of adding points on vertical line: %s\n", res)

	A := ecc.NewEllipticCurvePoint(big.NewInt(2), big.NewInt(5), big.NewInt(5), big.NewInt(7))
	B := ecc.NewEllipticCurvePoint(big.NewInt(-1), big.NewInt(-1), big.NewInt(5), big.NewInt(7))

	C := A.Add(B)

	fmt.Printf("A(2,5)+B(-1,-1) = %s\n", C)

	C = B.Add(B)
	fmt.Printf("A(-1,-1)+B(-1,-1) = %s\n", C)
}
