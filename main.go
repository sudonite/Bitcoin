package main

import (
	"fmt"
	"math/big"
	"math/rand"

	ecc "github.com/sudonite/bitcoin/elliptic_curve"
)

func SolvField19MultiplieSet() {
	min := 1
	max := 18

	k := rand.Intn(max-min) + min
	fmt.Printf("Randomly select k is %d\n", k)

	element := ecc.NewFieldElement(big.NewInt(19), big.NewInt(int64(k)))

	for i := range 19 {
		fmt.Printf("element %d multipie with %d is %v\n", k, i, element.ScalarMul(big.NewInt(int64(i))))
	}
}

func ComputeFieldOrderPower() {
	orders := []int{7, 11, 17, 19, 31}
	for _, p := range orders {
		fmt.Printf("value of p is %d\n", p)
		for i := 1; i < p; i++ {
			elm := ecc.NewFieldElement(big.NewInt(int64(p)), big.NewInt(int64(i)))
			fmt.Printf("for element %v, its power of p - 1 is %v\n", elm, elm.Power(big.NewInt(int64(p-1))))
		}
	}
}

func main() {
	f2 := ecc.NewFieldElement(big.NewInt(19), big.NewInt(2))
	f7 := ecc.NewFieldElement(big.NewInt(19), big.NewInt(7))
	fmt.Printf("field element 2 / 7 with order 19 is %v\n", f2.Divide(f7))

	f46 := ecc.NewFieldElement(big.NewInt(57), big.NewInt(46))
	fmt.Printf("field element 46 * 46 with order 57 is %v\n", f46.Multiply(f46))
	fmt.Printf("field element 46 with power 58 is %v\n", f46.Power(big.NewInt(58)))

	/*
		f44 := ecc.NewFieldElement(big.NewInt(57), big.NewInt(44))
		f33 := ecc.NewFieldElement(big.NewInt(57), big.NewInt(33))
		res := f44.Add(f33)
		fmt.Printf("field element 44 add to field element 33 is %v\n", res)
		fmt.Printf("negate of field element 44 is %v\n", f44.Negate())

		fmt.Printf("field element 44 - 33 is %v\n", f44.Subtract(f33))
		fmt.Printf("field element 33 - 44 is %v\n", f33.Subtract(f44))

		fmt.Printf("check 46 + 44 over modulur 57 %v\n", (46+44)%57)
		f46 := ecc.NewFieldElement(big.NewInt(57), big.NewInt(46))
		fmt.Printf("field element 46 + 44 is %v\n", (f46.Add(f44)))
		SolvField19MultiplieSet()
		ComputeFieldOrderPower()
	*/
}
