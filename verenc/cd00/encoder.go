package cd00

import (
	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type sigmaEncoder[G curve.Curve, P sigma.Protocol] interface {
	sigma.Encoder[G, P]
}

type Encoder[G curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	sigmaEncoder[G, P]
}

func newEncoder[G curve.Curve, P sigma.Protocol, E probenc.Scheme](sigmaE sigma.Encoder[G, P]) *Encoder[G, P, E] {
	return &Encoder[G, P, E]{
		sigmaEncoder: sigmaE,
	}
}

func (e *Encoder[G, P, E]) EncodeEncryptedResponses(resps []EncryptedResponse[G, P, E]) []byte {

}
