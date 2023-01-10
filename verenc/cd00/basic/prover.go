package basic

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Prover[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	sigmaP    sigma.Prover[C, P]
	sigmaV    sigma.Verifier[C, P]
	encoder   sigma.Encoder[C, P]
	encrypter probenc.Encrypter[E]
	rnd       io.Reader
}
type Commitment[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	t sigma.Commitment[C, P]
	e [2]probenc.Ciphertext[E]
}
type Decommitment[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	r [2]probenc.RandomBytes
	s [2]sigma.Response[C, P]
}
type Response[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	r probenc.RandomBytes
	s sigma.Response[C, P]
}

func NewProver[C curve.Curve, P sigma.Protocol, E probenc.Scheme](
	p sigma.Prover[C, P],
	v sigma.Verifier[C, P],
	encoder sigma.Encoder[C, P],
	encrypter probenc.Encrypter[E],
	rnd io.Reader,
) Prover[C, P, E] {
	return Prover[C, P, E]{
		sigmaP:    p,
		sigmaV:    v,
		encoder:   encoder,
		encrypter: encrypter,
		rnd:       rnd,
	}
}

func (p Prover[C, P, E]) Commit(
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
) (
	Commitment[C, P, E],
	Decommitment[C, P, E],
	error,
) {
	t, rt, err := p.sigmaP.Commit(x, w)
	if err != nil {
		return Commitment[C, P, E]{}, Decommitment[C, P, E]{}, fmt.Errorf("sigma protocol commit: %w", err)
	}

	ch0, ch1 := sigma.Challenge(false), sigma.Challenge(true)
	s0, s1 := p.sigmaP.Respond(x, w, rt, ch0), p.sigmaP.Respond(x, w, rt, ch1)
	s0Bytes, s1Bytes := p.encoder.EncodeResponse(s0), p.encoder.EncodeResponse(s1)
	e0, r0, err := probenc.Encrypt(p.rnd, s0Bytes, p.encrypter)
	if err != nil {
		return Commitment[C, P, E]{}, Decommitment[C, P, E]{}, fmt.Errorf("encrypting s0: %w", err)
	}
	e1, r1, err := probenc.Encrypt(p.rnd, s1Bytes, p.encrypter)
	if err != nil {
		return Commitment[C, P, E]{}, Decommitment[C, P, E]{}, fmt.Errorf("encrypting s1: %w", err)
	}

	com := Commitment[C, P, E]{
		t,
		[2]probenc.Ciphertext[E]{e0, e1},
	}
	decom := Decommitment[C, P, E]{
		[2]probenc.RandomBytes{r0, r1},
		[2]sigma.Response[C, P]{s0, s1},
	}
	return com, decom, nil
}

func (p Prover[C, P, E]) Respond(
	decom Decommitment[C, P, E],
	ch sigma.Challenge,
) Response[C, P, E] {
	chi := chtoi(ch)
	return Response[C, P, E]{decom.r[chi], decom.s[chi]}
}

func chtoi(ch sigma.Challenge) int {
	if ch {
		return 1
	}
	return 0
}
