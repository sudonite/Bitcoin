package elliptic_curve

import "fmt"

type Signature struct {
	r *FieldElement
	s *FieldElement
}

func NewSignature(r, s *FieldElement) *Signature {
	return &Signature{
		r: r,
		s: s,
	}
}

func (s *Signature) String() string {
	return fmt.Sprintf("Signature(r: {%s}, s: {%s})", s.r, s.s)
}
