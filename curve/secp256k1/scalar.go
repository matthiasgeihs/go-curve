package secp256k1

import (
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Scalar struct {
	v *secp.ModNScalar
}

// Check that type implements interface.
var _ curve.Scalar[Curve] = Scalar{}

func makeScalar(v *secp.ModNScalar) Scalar {
	return Scalar{
		v: v,
	}
}

func makeScalarFromBigInt(v *big.Int) Scalar {
	vMod := new(big.Int).Mod(v, secp.Params().N)
	var vScalar secp.ModNScalar
	overflow := vScalar.SetByteSlice(vMod.Bytes())
	if overflow {
		panic("overflow")
	}

	return Scalar{
		v: &vScalar,
	}
}

func (s Scalar) Inv() curve.Scalar[Curve] {
	inv := new(secp.ModNScalar).InverseValNonConst(s.v)
	return makeScalar(inv)
}

func (s Scalar) Add(t curve.Scalar[Curve]) curve.Scalar[Curve] {
	var sum secp.ModNScalar
	sum.Add2(s.v, t.(Scalar).v)
	return makeScalar(&sum)
}

func (s Scalar) Mul(t curve.Scalar[Curve]) curve.Scalar[Curve] {
	var prod secp.ModNScalar
	prod.Mul2(s.v, t.(Scalar).v)
	return makeScalar(&prod)
}

func (s Scalar) Int() *big.Int {
	b := s.v.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func (s Scalar) Equal(t curve.Scalar[Curve]) bool {
	return s.v.Equals(t.(Scalar).v)
}
