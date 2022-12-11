package binary

import (
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
)

type Verifier[C curve.Curve] struct {
	base dlog.Verifier[C]
	gen  curve.Generator[C]
	rnd  io.Reader
}

type Word[C curve.Curve] curve.Point[C]

func NewVerifier[C curve.Curve](
	gen curve.Generator[C],
	rnd io.Reader,
) Verifier[C] {
	v := dlog.NewVerifier(gen, rnd)
	return Verifier[C]{
		base: v,
		gen:  gen,
		rnd:  rnd,
	}
}

func (v Verifier[C]) Challenge(sigma.Commitment[C, Protocol]) (sigma.Challenge[C, Protocol], error) {
	b, err := v.sampleBool()
	return Challenge(b), err
}

func (v Verifier[C]) sampleBool() (bool, error) {
	var b [1]byte
	_, err := v.rnd.Read(b[:])
	return b[0]&1 == 1, err
}

func (v Verifier[C]) Verify(
	x sigma.Word[C, Protocol],
	com sigma.Commitment[C, Protocol],
	ch sigma.Challenge[C, Protocol],
	resp sigma.Response[C, Protocol],
) bool {
	chScalar := chToScalar(v.gen, ch.(Challenge))
	return v.base.Verify(x, com, chScalar, resp)
}
