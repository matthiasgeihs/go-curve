package cd00

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

type Prover[C curve.Curve, P sigma.Protocol] struct {
	sigmaP  sigma.Prover[C, P]
	sigmaV  sigma.Verifier[C, P]
	encoder sigma.Encoder[C, P]
}
type Commitment[C curve.Curve, P sigma.Protocol] struct {
	t        sigma.Commitment[C, P]
	ch0, ch1 sigma.Challenge[C, P]
	e0, e1   enc.Ciphertext
}
type Decommitment[C curve.Curve, P sigma.Protocol] struct {
	r0, r1 enc.Key
	s0, s1 sigma.Response[C, P]
}
type Response[C curve.Curve, P sigma.Protocol] struct {
	r enc.Key
	s sigma.Response[C, P]
}

func NewProver[C curve.Curve, P sigma.Protocol](
	p sigma.Prover[C, P],
	v sigma.Verifier[C, P],
	encoder sigma.Encoder[C, P],
) Prover[C, P] {
	return Prover[C, P]{
		sigmaP:  p,
		sigmaV:  v,
		encoder: encoder,
	}
}

func (p Prover[C, P]) Commit(
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	enc enc.Encrypt,
) (
	Commitment[C, P],
	Decommitment[C, P],
	error,
) {
	t, rt, err := p.sigmaP.Commit(x, w)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol commit: %w", err)
	}

	ch0, err := p.sigmaV.Challenge(t)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol challenge 1: %w", err)
	}
	ch1, err := p.sigmaV.Challenge(t)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol challenge 2: %w", err)
	}
	s0, s1 := p.sigmaP.Respond(x, w, rt, ch0), p.sigmaP.Respond(x, w, rt, ch1)
	s0Bytes, s1Bytes := p.encoder.EncodeResponse(s0), p.encoder.EncodeResponse(s1)
	e0, r0, err := enc(s0Bytes)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("encrypting s0: %w", err)
	}
	e1, r1, err := enc(s1Bytes)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("encrypting s1: %w", err)
	}

	com := Commitment[C, P]{t, ch0, ch1, e0, e1}
	decom := Decommitment[C, P]{r0, r1, s0, s1}
	return com, decom, nil
}

func (p Prover[C, P]) Respond(
	decom Decommitment[C, P],
	ch Challenge,
) Response[C, P] {
	if bool(ch) {
		return Response[C, P]{decom.r1, decom.s1}
	}
	return Response[C, P]{decom.r0, decom.s0}
}
