package sigma

import "github.com/matthiasgeihs/go-curve/curve"

type Protocol[C curve.Curve] interface{}

type Prover[C curve.Curve, P Protocol[C]] interface {
	Commit(
		Word[C, P],
		Witness[C, P],
	) (Commitment[C, P], Decommitment[C, P], error)
	Respond(
		Word[C, P],
		Witness[C, P],
		Commitment[C, P],
		Challenge[C, P],
	) Response[C, P]
}

type Verifier[C curve.Curve, P Protocol[C]] interface {
	Challenge(Commitment[C, P]) Challenge[C, P]
	Verify(Commitment[C, P], Response[C, P]) error
}

type Extractor[C curve.Curve, P Protocol[C]] interface {
	Extract(Transcript[C, P], Transcript[C, P]) Witness[C, P]
}

type Encoder[C curve.Curve, P Protocol[C]] interface {
	EncodeResponse(Response[C, P]) []byte
	DecodeResponse([]byte) Response[C, P]
}

type Word[C curve.Curve, P Protocol[C]] interface{}
type Witness[C curve.Curve, P Protocol[C]] interface{}
type Commitment[C curve.Curve, P Protocol[C]] interface{}
type Decommitment[C curve.Curve, P Protocol[C]] interface{}
type Challenge[C curve.Curve, P Protocol[C]] interface{}
type Response[C curve.Curve, P Protocol[C]] interface{}

type Transcript[C curve.Curve, P Protocol[C]] struct {
	Challenge Challenge[C, P]
	Response  Response[C, P]
}

func MakeTranscript[C curve.Curve, P Protocol[C]](
	c Challenge[C, P],
	r Response[C, P],
) Transcript[C, P] {
	return Transcript[C, P]{
		Challenge: c,
		Response:  r,
	}
}
