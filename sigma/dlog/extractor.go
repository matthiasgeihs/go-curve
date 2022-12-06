package dlog

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Extractor[C curve.Curve] struct {
	gen curve.Generator[C]
}

func NewExtractor[C curve.Curve](
	gen curve.Generator[C],
) Extractor[C] {
	return Extractor[C]{
		gen: gen,
	}
}

func (ext Extractor[C]) Extract(t1, t2 sigma.Transcript[C]) sigma.Witness[C] {
	s1 := t1.Response.(Response[C])
	s2 := t2.Response.(Response[C])
	s1s2 := s1.Sub(s2)

	c1 := t1.Challenge.(Challenge[C])
	c2 := t2.Challenge.(Challenge[C])
	c1c2 := c1.Sub(c2)

	w := s1s2.Mul(c1c2.Inv())
	return w
}
