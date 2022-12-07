package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Prover[C curve.Curve] struct {
	gen curve.Generator[C]
	rnd io.Reader
	w   Witness[C]
}

type Witness[C curve.Curve] curve.Scalar[C]
type Commitment[C curve.Curve] curve.Point[C]
type Decommitment[C curve.Curve] curve.Scalar[C]
type Challenge[C curve.Curve] curve.Scalar[C]
type Response[C curve.Curve] curve.Scalar[C]

func NewProver[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
	w Witness[C],
) Prover[C] {
	return Prover[C]{
		gen: gen,
		rnd: rnd,
		w:   w,
	}
}

func (p Prover[C]) Commit() (sigma.Commitment[C], sigma.Decommitment[C], error) {
	r, err := p.gen.RandomScalar(p.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("sampling scalar: %w", err)
	}

	t := p.gen.Generator().Mul(r)
	return Commitment[C](t), Decommitment[C](r), nil
}

func (p Prover[C]) Respond(
	decom sigma.Decommitment[C],
	ch sigma.Challenge[C],
) sigma.Response[C] {
	r := decom.(Decommitment[C])
	c := ch.(Challenge[C])
	s := r.Add(c.Mul(p.w))
	return Response[C](s)
}
