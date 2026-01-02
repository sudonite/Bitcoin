package elliptic_curve

import "fmt"

// Stores an ECDSA signature values
type Signature struct {
	r *FieldElement
	s *FieldElement
}

// Creates a new signature object
func NewSignature(r, s *FieldElement) *Signature {
	return &Signature{
		r: r,
		s: s,
	}
}

// Returns signature as string
func (s *Signature) String() string {
	return fmt.Sprintf("Signature(r: {%s}, s: {%s})", s.r, s.s)
}

// Serializes the signature to DER format
func (s *Signature) Der() []byte {
	rBin := s.r.num.Bytes()
	if rBin[0] >= 0x80 {
		rBin = append([]byte{0x00}, rBin...)
	}
	rBin = append([]byte{0x02, byte(len(rBin))}, rBin...)

	sBin := s.s.num.Bytes()
	if sBin[0] >= 0x80 {
		sBin = append([]byte{0x00}, sBin...)
	}
	sBin = append([]byte{0x02, byte(len(sBin))}, sBin...)

	derBin := append([]byte{0x30, byte(len(rBin) + len(sBin))}, rBin...)
	derBin = append(derBin, sBin...)

	return derBin
}
