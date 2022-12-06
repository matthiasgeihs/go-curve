package edwards25519

import (
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Point struct {
	p *edwards25519.Point
}

// Check that type implements interface.
var _ curve.Point[Curve] = Point{}

func makePoint(p *edwards25519.Point) Point {
	return Point{
		p: p,
	}
}

func makePointFromAffine(x, y *big.Int) Point {
	xf := newFieldElement(x)
	yf := newFieldElement(y)
	zf := newFieldElement(big.NewInt(1))
	tf := new(field.Element).Multiply(xf, yf)

	jp, err := new(edwards25519.Point).SetExtendedCoordinates(xf, yf, zf, tf)
	if err != nil {
		panic(err)
	}
	return makePoint(jp)
}

// makePointFromAffineX computes a point from an x-coordinate.
func makePointFromAffineX(x *big.Int) (Point, error) {
	xf := newFieldElement(x)
	p, err := new(edwards25519.Point).SetBytes(xf.Bytes())
	if err != nil {
		return Point{}, fmt.Errorf("creating point from bytes: %w", err)
	}
	return makePoint(p), nil
}

func newFieldElement(v *big.Int) *field.Element {
	vMod := new(big.Int).Mod(v, fieldOrder)
	b := littleEndian(vMod)
	buf := make([]byte, fieldElementSize)
	copy(buf, b)
	fe, err := new(field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return fe
}

func (p Point) X() *big.Int {
	x, _, z, _ := p.p.ExtendedCoordinates()
	zinv := new(field.Element).Invert(z)
	ax := new(field.Element).Multiply(x, zinv)
	b := ax.Bytes()
	reverse(b)
	return new(big.Int).SetBytes(b)
}

func (p Point) Y() *big.Int {
	_, y, z, _ := p.p.ExtendedCoordinates()
	zinv := new(field.Element).Invert(z)
	ay := new(field.Element).Multiply(y, zinv)
	b := ay.Bytes()
	reverse(b)
	return new(big.Int).SetBytes(b)
}

func (p Point) Add(q curve.Point[Curve]) curve.Point[Curve] {
	sum := new(edwards25519.Point).Add(p.p, q.(Point).p)
	return makePoint(sum)
}

func (p Point) Mul(s curve.Scalar[Curve]) curve.Point[Curve] {
	prod := new(edwards25519.Point).ScalarMult(s.(Scalar).v, p.p)
	return makePoint(prod)
}
