package secp256k1

import (
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Point struct {
	p *secp.JacobianPoint
}

// Check that type implements interface.
var _ curve.Point[Curve] = Point{}

func makePoint(p *secp.JacobianPoint) Point {
	return Point{
		p: p,
	}
}

// makePointFromAffineX computes a point from an x-coordinate. Panics if such a
// point does not exist.
func makePointFromAffineX(x *big.Int) Point {
	fx := makeFieldVal(x)
	ySquared := new(secp.FieldVal).SquareVal(fx).Mul(fx).AddInt(7).Normalize()
	fy := new(secp.FieldVal)
	success := fy.SquareRootVal(ySquared)
	if !success {
		panic("failed to compute square root")
	}
	p := secp.MakeJacobianPoint(
		fx,
		fy,
		makeFieldVal(big.NewInt(1)),
	)
	return makePoint(&p)
}

func makeFieldVal(v *big.Int) *secp.FieldVal {
	vMod := new(big.Int).Mod(v, secp.Params().P)
	var vf secp.FieldVal
	vf.SetByteSlice(vMod.Bytes())
	return &vf
}

func makePointBigInt(x, y *big.Int) Point {
	jp := secp.MakeJacobianPoint(
		makeFieldVal(x),
		makeFieldVal(y),
		makeFieldVal(big.NewInt(1)),
	)
	return makePoint(&jp)
}

func (p Point) X() *big.Int {
	p.p.ToAffine()
	b := p.p.X.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func (p Point) Y() *big.Int {
	p.p.ToAffine()
	b := p.p.X.Bytes()
	return new(big.Int).SetBytes(b[:])
}

func (p Point) Add(q curve.Point[Curve]) curve.Point[Curve] {
	var sum secp.JacobianPoint
	secp.AddNonConst(p.p, q.(Point).p, &sum)
	return makePoint(&sum)
}

func (p Point) Mul(s curve.Scalar[Curve]) curve.Point[Curve] {
	var prod secp.JacobianPoint
	secp.ScalarMultNonConst(s.(Scalar).v, p.p, &prod)
	return makePoint(&prod)
}
