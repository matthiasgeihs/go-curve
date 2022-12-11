package dlog

import (
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Encoder[C curve.Curve] struct {
	gen curve.Generator[C]
}

func NewEncoder[C curve.Curve](gen curve.Generator[C]) Encoder[C] {
	return Encoder[C]{
		gen: gen,
	}
}

func (e Encoder[C]) EncodeResponse(resp sigma.Response[C, Protocol]) []byte {
	dlogResp := resp.(Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C]) DecodeResponse(data []byte) sigma.Response[C, Protocol] {
	bi := new(big.Int).SetBytes(data)
	return Response[C](e.gen.NewScalar(bi))
}

func (e Encoder[C]) EncodeWitness(w sigma.Witness[C, Protocol]) []byte {
	dlogResp := w.(Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C]) DecodeWitness(data []byte) sigma.Witness[C, Protocol] {
	bi := new(big.Int).SetBytes(data)
	return Witness[C](e.gen.NewScalar(bi))
}
