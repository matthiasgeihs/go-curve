package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Verifier[C curve.Curve] struct {
	gen  curve.Generator[C]
	rnd  io.Reader
	word Word[C]
}

type Word[C curve.Curve] curve.Point[C]

func NewVerifier[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
	w Word[C],
) Verifier[C] {
	return Verifier[C]{
		gen:  gen,
		rnd:  rnd,
		word: w,
	}
}

func (v Verifier[C]) Challenge(sigma.Commitment[C]) (sigma.Challenge[C], error) {
	c, err := v.gen.RandomScalar(v.rnd)
	if err != nil {
		return nil, fmt.Errorf("sampling scalar: %w", err)
	}

	return c, nil
}

func (v Verifier[C]) Verify(com sigma.Commitment[C], ch sigma.Challenge[C], resp sigma.Response[C]) error {
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
