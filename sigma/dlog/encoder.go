package dlog

import (
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Encoder[C curve.Curve, P sigma.Protocol] struct {
	gen curve.Generator[C]
}

func NewEncoder[C curve.Curve, P sigma.Protocol](gen curve.Generator[C]) Encoder[C, P] {
	return Encoder[C, P]{
		gen: gen,
	}
}

func (e Encoder[C, P]) EncodeResponse(resp sigma.Response[C, P]) []byte {
	dlogResp := resp.(Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C, P]) DecodeResponse(data []byte) sigma.Response[C, P] {
	bi := new(big.Int).SetBytes(data)
	return Response[C](e.gen.NewScalar(bi))
}

func (e Encoder[C, P]) EncodeWitness(w sigma.Witness[C, P]) []byte {
	dlogResp := w.(Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C, P]) DecodeWitness(data []byte) sigma.Witness[C, P] {
	bi := new(big.Int).SetBytes(data)
	return Witness[C](e.gen.NewScalar(bi))
}
