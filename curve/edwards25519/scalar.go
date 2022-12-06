package edwards25519

import (
	"math/big"

	"filippo.io/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Scalar struct {
	v *edwards25519.Scalar
}

// Check that type implements interface.
var _ curve.Scalar[Curve] = Scalar{}

func makeScalar(v *edwards25519.Scalar) Scalar {
	return Scalar{
		v: v,
	}
}

func makeScalarFromBigInt(v *big.Int) Scalar {
	vMod := new(big.Int).Mod(v, generatorOrder)
	le := littleEndian(vMod, scalarByteSize)
	vScalar, err := edwards25519.NewScalar().SetCanonicalBytes(le)
	if err != nil {
		panic(err)
	}

	return Scalar{
		v: vScalar,
	}
}

// littleEndian computes the little endian representation of v with length l.
func littleEndian(v *big.Int, l int) []byte {
	vb := v.Bytes()
	reverse(vb)
	buf := make([]byte, l)
	copy(buf, vb)
	return buf
}

// Reverse slice in-place.
func reverse[T any](b []T) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

func (s Scalar) Inv() curve.Scalar[Curve] {
	inv := edwards25519.NewScalar().Invert(s.v)
	return makeScalar(inv)
}

func (s Scalar) Add(t curve.Scalar[Curve]) curve.Scalar[Curve] {
	sum := edwards25519.NewScalar().Add(s.v, t.(Scalar).v)
	return makeScalar(sum)
}

func (s Scalar) Sub(t curve.Scalar[Curve]) curve.Scalar[Curve] {
	sum := edwards25519.NewScalar().Subtract(s.v, t.(Scalar).v)
	return makeScalar(sum)
}

func (s Scalar) Mul(t curve.Scalar[Curve]) curve.Scalar[Curve] {
	prod := edwards25519.NewScalar().Multiply(s.v, t.(Scalar).v)
	return makeScalar(prod)
}

func (s Scalar) Int() *big.Int {
	b := s.v.Bytes()
	reverse(b)
	return new(big.Int).SetBytes(b[:])
}

func (s Scalar) Equal(t curve.Scalar[Curve]) bool {
	return s.v.Equal(t.(Scalar).v) == 1
}
