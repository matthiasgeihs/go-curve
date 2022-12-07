package cd00

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

type Verifier[C curve.Curve, P sigma.Protocol[C]] struct {
	rnd    io.Reader
	sigmaV sigma.Verifier[C, P]
}
type Word[C curve.Curve] curve.Point[C]
type Challenge bool
type Ciphertext[C curve.Curve, P sigma.Protocol[C]] struct {
	c      Challenge
	c0, c1 sigma.Challenge[C, P]
	e      enc.Ciphertext
	s      sigma.Response[C, P]
}

func (v Verifier[C, P]) Challenge(Commitment[C, P]) Challenge {
	c := func() bool {
		var b [1]byte
		v.rnd.Read(b[:])
		return b[0]&1 == 1
	}()
	return Challenge(c)
}

func (v Verifier[C, P]) Verify(
	x sigma.Word[C, P],
	com Commitment[C, P],
	ch Challenge,
	resp Response[C, P],
) (Ciphertext[C, P], error) {
	sigmaCh := func() sigma.Challenge[C, P] {
		if ch {
			return com.ch1
		}
		return com.ch0
	}()

	b := v.sigmaV.Verify(x, com.t, sigmaCh, resp.s)
	if !b {
		return Ciphertext[C, P]{}, fmt.Errorf("invalid")
	}

	e := func() enc.Ciphertext {
		if ch {
			return com.e1
		}
		return com.e0
	}()
	return Ciphertext[C, P]{ch, com.ch0, com.ch1, e, resp.s}, nil
}
