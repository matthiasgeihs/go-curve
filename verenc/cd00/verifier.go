package cd00

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Verifier[C curve.Curve, P sigma.Protocol[C]] struct {
	rnd    io.Reader
	sigmaV sigma.Verifier[C, P]
}
type Word[C curve.Curve] curve.Point[C]
type Challenge bool
type Ciphertext[C curve.Curve, P sigma.Protocol[C]] struct{}

func (v Verifier[C, P]) Challenge(
	sigma.Commitment[C, P],
) (
	sigma.Challenge[C, P],
	error,
) {
	c := func() byte {
		var b [1]byte
		v.rnd.Read(b[:])
		return b[0] & 1
	}()
	return c, nil
}

func (v Verifier[C, P]) Verify(
	x sigma.Word[C, P],
	com Commitment[C, P],
	ch sigma.Challenge[C, P],
	resp sigma.Response[C, P],
) (Ciphertext[C, P], error) {
	b := v.sigmaV.Verify(x, com.t, ch, resp.s)
	if !b {
		return nil, fmt.Errorf("invalid")
	}
	return Ciphertext[C]{c, com.e[notC], resp.s, resp.t}
}
