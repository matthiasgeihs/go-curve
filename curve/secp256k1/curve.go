package secp256k1

import (
	"crypto/sha256"
	"io"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Curve struct {
	encoder curve.Encoder[Curve]
}

// Check that type implements interface.
var _ curve.Generator[Curve] = Curve{}

func NewGenerator() Curve {
	const fieldSize = 32
	const maxMessageLength = fieldSize / 2
	return Curve{
		encoder: curve.NewEncoder(
			fieldSize,
			secp.Params().P,
			maxMessageLength,
			func(i *big.Int) (curve.Point[Curve], error) {
				return makePointFromAffineX(i)
			},
		),
	}
}

func (Curve) NewPoint(x, y *big.Int) curve.Point[Curve] {
	return makePointBigInt(x, y)
}

func (Curve) Generator() curve.Point[Curve] {
	params := secp.Params()
	return makePointBigInt(params.Gx, params.Gy)
}

func (Curve) GeneratorOrder() *big.Int {
	return new(big.Int).Set(secp.Params().N)
}

func (Curve) RandomScalar(rand io.Reader) (curve.Scalar[Curve], error) {
	buf := make([]byte, secp.Params().ByteSize)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	rbi := new(big.Int).SetBytes(buf)
	return makeScalarFromBigInt(rbi), nil
}

func (Curve) NewScalar(v *big.Int) curve.Scalar[Curve] {
	return makeScalarFromBigInt(v)
}

func (Curve) HashToScalar(data []byte) curve.Scalar[Curve] {
	h := sha256.Sum256(data)
	var v secp.ModNScalar
	v.SetByteSlice(h[:])
	return makeScalar(&v)
}

func (c Curve) EncodeToPoint(data []byte) (curve.Point[Curve], error) {
	return c.encoder.EncodeToPoint(data)
}

func (c Curve) DecodeFromPoint(p curve.Point[Curve]) []byte {
	return c.encoder.DecodeFromPoint(p)
}
