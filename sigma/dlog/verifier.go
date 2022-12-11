package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Verifier[C curve.Curve] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

type Word[C curve.Curve] curve.Point[C]

func NewVerifier[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
) Verifier[C] {
	return Verifier[C]{
		gen: gen,
		rnd: rnd,
	}
}

func (v Verifier[C]) Challenge(sigma.Commitment[C, Protocol]) (sigma.Challenge[C, Protocol], error) {
	c, err := v.gen.RandomScalar(v.rnd)
	if err != nil {
		return nil, fmt.Errorf("sampling scalar: %w", err)
	}
	return c, nil
}

func (v Verifier[C]) Verify(
	x sigma.Word[C, Protocol],
	com sigma.Commitment[C, Protocol],
	ch sigma.Challenge[C, Protocol],
	resp sigma.Response[C, Protocol],
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
