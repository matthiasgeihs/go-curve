package binary

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Protocol interface{}

type Prover[C curve.Curve, P Protocol] interface {
	Commit(
		Word[C, P],
		Witness[C, P],
	) (Commitment[C, P], Decommitment[C, P], error)
	Respond(
		Word[C, P],
		Witness[C, P],
		Decommitment[C, P],
		Challenge,
	) Response[C, P]
}

type Verifier[C curve.Curve, P Protocol] interface {
	Challenge(Commitment[C, P]) (Challenge, error)
	Verify(Word[C, P], Commitment[C, P], Challenge, Response[C, P]) bool
}

type Extractor[C curve.Curve, P Protocol] interface {
	Extract(Transcript[C, P], Transcript[C, P]) Witness[C, P]
}

type Encoder[C curve.Curve, P Protocol] interface {
	EncodeResponse(Response[C, P]) []byte
	DecodeResponse([]byte) Response[C, P]
	EncodeWitness(Witness[C, P]) []byte
	DecodeWitness([]byte) Witness[C, P]
}

type Word[C curve.Curve, P Protocol] sigma.Word[C, P]
type Witness[C curve.Curve, P Protocol] sigma.Witness[C, P]
type Commitment[C curve.Curve, P Protocol] sigma.Commitment[C, P]
type Decommitment[C curve.Curve, P Protocol] sigma.Decommitment[C, P]
type Response[C curve.Curve, P Protocol] sigma.Response[C, P]

type Challenge bool
type Transcript[C curve.Curve, P Protocol] struct {
	Challenge Challenge
	Response  Response[C, P]
}

func MakeTranscript[C curve.Curve, P Protocol](
	c Challenge,
	r Response[C, P],
) Transcript[C, P] {
	return Transcript[C, P]{
		Challenge: c,
		Response:  r,
	}
}
