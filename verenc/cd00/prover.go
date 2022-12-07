package cd00

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

type Prover[C curve.Curve, P sigma.Protocol[C]] struct {
	sigmaP  sigma.Prover[C, P]
	sigmaV  sigma.Verifier[C, P]
	encoder sigma.Encoder[C, P]
}
type Commitment[C curve.Curve, P sigma.Protocol[C]] struct {
	t        sigma.Commitment[C, P]
	ch0, ch1 sigma.Challenge[C, P]
	e0, e1   enc.Ciphertext
}
type Decommitment[C curve.Curve, P sigma.Protocol[C]] struct {
	r0, r1 enc.Key
	s0, s1 sigma.Response[C, P]
}
type Response[C curve.Curve, P sigma.Protocol[C]] struct {
	r enc.Key
	s sigma.Response[C, P]
}

func (p Prover[C, P]) Commit(
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	enc enc.Encrypt[C, P],
) (
	Commitment[C, P],
	Decommitment[C, P],
	error,
) {
	t, rt, err := p.sigmaP.Commit(x, w)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol commit: %w", err)
	}

	ch0, ch1 := p.sigmaV.Challenge(t), p.sigmaV.Challenge(t)
	s0, s1 := p.sigmaP.Respond(x, w, rt, ch0), p.sigmaP.Respond(x, w, rt, ch1)
	s0Bytes, s1Bytes := p.encoder.EncodeResponse(s0), p.encoder.EncodeResponse(s1)
	e0, r0 := enc(s0Bytes)
	e1, r1 := enc(s1Bytes)

	com := Commitment[C, P]{t, ch0, ch1, e0, e1}
	decom := Decommitment[C, P]{r0, r1, s0, s1}
	return com, decom, nil
}

func (p Prover[C, P]) Respond(
	decom Decommitment[C, P],
	ch Challenge,
) Response[C, P] {
	if bool(ch) {
		return Response[C, P]{decom.r0, decom.s0}
	}
	return Response[C, P]{decom.r1, decom.s1}
}
