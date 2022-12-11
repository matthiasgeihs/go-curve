package dlog

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Protocol struct{}

type Prover[C curve.Curve] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

type Witness[C curve.Curve] curve.Scalar[C]
type Commitment[C curve.Curve] curve.Point[C]
type Decommitment[C curve.Curve] curve.Scalar[C]
type Challenge[C curve.Curve] curve.Scalar[C]
type Response[C curve.Curve] curve.Scalar[C]

func NewProver[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
) Prover[C] {
	return Prover[C]{
		gen: gen,
		rnd: rnd,
	}
}

func (p Prover[C]) Commit(
	sigma.Word[C, Protocol],
	sigma.Witness[C, Protocol],
) (
	sigma.Commitment[C, Protocol],
	sigma.Decommitment[C, Protocol],
	error,
) {
	r, err := p.gen.RandomScalar(p.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("sampling scalar: %w", err)
	}

	t := p.gen.Generator().Mul(r)
	return Commitment[C](t), Decommitment[C](r), nil
}

func (p Prover[C]) Respond(
	_ sigma.Word[C, Protocol],
	w sigma.Witness[C, Protocol],
	decom sigma.Decommitment[C, Protocol],
	ch sigma.Challenge[C, Protocol],
) sigma.Response[C, Protocol] {
	r := decom.(Decommitment[C])
	c := ch.(Challenge[C])
	dlogW := w.(Witness[C])
	s := r.Add(c.Mul(dlogW))
	return Response[C](s)
}
