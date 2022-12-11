package binary

import (
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
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
	dlogResp := resp.(dlog.Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C]) DecodeResponse(data []byte) sigma.Response[C, Protocol] {
	bi := new(big.Int).SetBytes(data)
	return dlog.Response[C](e.gen.NewScalar(bi))
}

func (e Encoder[C]) EncodeWitness(w sigma.Witness[C, Protocol]) []byte {
	dlogResp := w.(dlog.Response[C])
	return dlogResp.Int().Bytes()
}

func (e Encoder[C]) DecodeWitness(data []byte) sigma.Witness[C, Protocol] {
	bi := new(big.Int).SetBytes(data)
	return dlog.Witness[C](e.gen.NewScalar(bi))
}
