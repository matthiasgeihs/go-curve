package sigma

import "github.com/matthiasgeihs/go-curve/curve"

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
		Challenge[C, P],
	) Response[C, P]
}

type Verifier[C curve.Curve, P Protocol] interface {
	Challenge(Commitment[C, P]) (Challenge[C, P], error)
	Verify(Word[C, P], Commitment[C, P], Challenge[C, P], Response[C, P]) bool
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

type Word[C curve.Curve, P Protocol] interface{}
type Witness[C curve.Curve, P Protocol] interface{}
type Commitment[C curve.Curve, P Protocol] interface{}
type Decommitment[C curve.Curve, P Protocol] interface{}
type Challenge[C curve.Curve, P Protocol] interface{}
type Response[C curve.Curve, P Protocol] interface{}

type Transcript[C curve.Curve, P Protocol] struct {
	Challenge Challenge[C, P]
	Response  Response[C, P]
}

func MakeTranscript[C curve.Curve, P Protocol](
	c Challenge[C, P],
	r Response[C, P],
) Transcript[C, P] {
	return Transcript[C, P]{
		Challenge: c,
		Response:  r,
	}
}
