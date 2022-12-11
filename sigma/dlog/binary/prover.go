package binary

import (
	"io"
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
)

type Protocol struct{}

type Prover[C curve.Curve] struct {
	base dlog.Prover[C]
	gen  curve.Generator[C]
}

type Challenge bool

func NewProver[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
) Prover[C] {
	p := dlog.NewProver(gen, rnd)
	return Prover[C]{
		base: p,
		gen:  gen,
	}
}

func (p Prover[C]) Commit(
	x sigma.Word[C, Protocol],
	w sigma.Witness[C, Protocol],
) (
	sigma.Commitment[C, Protocol],
	sigma.Decommitment[C, Protocol],
	error,
) {
	return p.base.Commit(x, w)
}

func (p Prover[C]) Respond(
	x sigma.Word[C, Protocol],
	w sigma.Witness[C, Protocol],
	decom sigma.Decommitment[C, Protocol],
	ch sigma.Challenge[C, Protocol],
) sigma.Response[C, Protocol] {
	chScalar := chToScalar(p.gen, ch.(Challenge))
	resp := p.base.Respond(x, w, decom, chScalar)
	return resp
}

func chToScalar[C curve.Curve](gen curve.Generator[C], ch Challenge) curve.Scalar[C] {
	i := boolToInt64(bool(ch))
	bi := big.NewInt(i)
	return gen.NewScalar(bi)
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
