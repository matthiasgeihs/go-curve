package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Verifier[C curve.Curve, P sigma.Protocol[C]] struct {
	gen  curve.Generator[C]
	rnd  io.Reader
	word Word[C]
}

type Word[C curve.Curve] curve.Point[C]

func NewVerifier[C curve.Curve, P sigma.Protocol[C]](
	gen curve.Generator[C],
	rnd io.Reader,
	w Word[C],
) Verifier[C, P] {
	return Verifier[C, P]{
		gen:  gen,
		rnd:  rnd,
		word: w,
	}
}

func (v Verifier[C, P]) Challenge(sigma.Commitment[C, P]) (sigma.Challenge[C, P], error) {
	c, err := v.gen.RandomScalar(v.rnd)
	if err != nil {
		return nil, fmt.Errorf("sampling scalar: %w", err)
	}

	return c, nil
}

func (v Verifier[C, P]) Verify(com sigma.Commitment[C, P], ch sigma.Challenge[C, P], resp sigma.Response[C, P]) error {
	t := com.(Commitment[C])
	c := ch.(Challenge[C])
	s := resp.(Response[C])
	gs := v.gen.Generator().Mul(s)
	tyc := t.Add(curve.Point[C](v.word).Mul(c))
	if gs.X().Cmp(tyc.X()) != 0 {
		return fmt.Errorf("invalid")
	}
	return nil
}
