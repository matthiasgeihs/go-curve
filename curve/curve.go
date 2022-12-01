package curve

import (
	"io"
	"math/big"
)

type Curve interface{}

// Curve with prime order subgroup.
type Generator[C Curve] interface {
	Generator() Point[C]
	GeneratorOrder() *big.Int
	NewPoint(*big.Int, *big.Int) Point[C]
	RandomScalar(io.Reader) (Scalar[C], error)
	NewScalar(*big.Int) Scalar[C]
	HashToScalar([]byte) Scalar[C]
	EncodeToPoint([]byte) (Point[C], error)
	DecodeFromPoint(Point[C]) []byte
}

type Point[C Curve] interface {
	X() *big.Int
	Y() *big.Int
	Add(q Point[C]) Point[C]
	Mul(Scalar[C]) Point[C]
}

type Scalar[C Curve] interface {
	Inv() Scalar[C]
	Add(Scalar[C]) Scalar[C]
	Mul(Scalar[C]) Scalar[C]
	Int() *big.Int
	Equal(Scalar[C]) bool
}
