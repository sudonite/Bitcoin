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
