package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Protocol interface{}

type Prover[C curve.Curve, P sigma.Protocol] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

type Witness[C curve.Curve] curve.Scalar[C]
type Commitment[C curve.Curve] curve.Point[C]
type Decommitment[C curve.Curve] curve.Scalar[C]
type Challenge[C curve.Curve] curve.Scalar[C]
type Response[C curve.Curve] curve.Scalar[C]

func NewProver[C curve.Curve, P sigma.Protocol](
	gen curve.Generator[C],
	rnd io.Reader,
) Prover[C, P] {
	return Prover[C, P]{
		gen: gen,
		rnd: rnd,
	}
}

func (p Prover[C, P]) Commit(
	sigma.Word[C, P],
	sigma.Witness[C, P],
) (
	sigma.Commitment[C, P],
	sigma.Decommitment[C, P],
	error,
) {
	r, err := p.gen.RandomScalar(p.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("sampling scalar: %w", err)
	}

	t := p.gen.Generator().Mul(r)
	return Commitment[C](t), Decommitment[C](r), nil
}

func (p Prover[C, P]) Respond(
	_ sigma.Word[C, P],
	w sigma.Witness[C, P],
	decom sigma.Decommitment[C, P],
	ch sigma.Challenge[C, P],
) sigma.Response[C, P] {
	r := decom.(Decommitment[C])
	c := ch.(Challenge[C])
	dlogW := w.(Witness[C])
	s := r.Add(c.Mul(dlogW))
	return Response[C](s)
}
