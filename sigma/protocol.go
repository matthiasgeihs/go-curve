package sigma

import "github.com/matthiasgeihs/go-curve/curve"

type Prover[C curve.Curve] interface {
	Commit() (Commitment[C], Decommitment[C], error)
	Respond(Challenge[C]) Response[C]
}

type Verifier[C curve.Curve] interface {
	Challenge(Commitment[C]) Challenge[C]
	Verify(Commitment[C], Response[C]) error
}

type Extractor[C curve.Curve] interface {
	Extract(Transcript[C], Transcript[C]) Witness[C]
}

type Witness[C curve.Curve] interface{}
type Commitment[C curve.Curve] interface{}
type Decommitment[C curve.Curve] interface{}
type Challenge[C curve.Curve] interface{}
type Response[C curve.Curve] interface{}

type Transcript[C curve.Curve] struct {
	Challenge Challenge[C]
	Response  Response[C]
}

func MakeTranscript[C curve.Curve](
	c Challenge[C],
	r Response[C],
) Transcript[C] {
	return Transcript[C]{
		Challenge: c,
		Response:  r,
	}
}
