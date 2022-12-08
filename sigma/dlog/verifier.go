package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Verifier[C curve.Curve, P sigma.Protocol] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

type Word[C curve.Curve] curve.Point[C]

func NewVerifier[C curve.Curve, P sigma.Protocol](
	gen curve.Generator[C],
	rnd io.Reader,
) Verifier[C, P] {
	return Verifier[C, P]{
		gen: gen,
		rnd: rnd,
	}
}

func (v Verifier[C, P]) Challenge(sigma.Commitment[C, P]) (sigma.Challenge[C, P], error) {
	c, err := v.gen.RandomScalar(v.rnd)
	if err != nil {
		return nil, fmt.Errorf("sampling scalar: %w", err)
	}
	return c, nil
}

func (v Verifier[C, P]) Verify(
	x sigma.Word[C, P],
	com sigma.Commitment[C, P],
	ch sigma.Challenge[C, P],
	resp sigma.Response[C, P],
) bool {
	t := com.(Commitment[C])
	c := ch.(Challenge[C])
	s := resp.(Response[C])
	gs := v.gen.Generator().Mul(s)
	dlogX := x.(Word[C])
	tyc := t.Add(curve.Point[C](dlogX).Mul(c))
	valid := gs.X().Cmp(tyc.X()) == 0
	return valid
}
