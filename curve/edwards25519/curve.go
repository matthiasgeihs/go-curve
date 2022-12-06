package edwards25519

import (
	"crypto/sha256"
	"io"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Curve struct {
	encoder curve.Encoder[Curve]
}

var generatorOrder, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
var fieldOrder, _ = new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16)

const scalarByteSize = 32
const fieldElementSize = 32

// Check that type implements interface.
var _ curve.Generator[Curve] = Curve{}

func NewGenerator() Curve {
	const maxMessageLength = fieldElementSize / 2
	return Curve{
		encoder: curve.NewEncoder(
			fieldElementSize,
			fieldOrder,
			maxMessageLength,
			func(i *big.Int) (curve.Point[Curve], error) {
				return makePointFromAffineX(i)
			},
		),
	}
}

func (Curve) NewPoint(x, y *big.Int) curve.Point[Curve] {
	return makePointFromAffine(x, y)
}

func (Curve) Generator() curve.Point[Curve] {
	g := edwards25519.NewGeneratorPoint()
	return makePoint(g)
}

func (Curve) GeneratorOrder() *big.Int {
	return new(big.Int).Set(generatorOrder)
}

func (Curve) RandomScalar(rand io.Reader) (curve.Scalar[Curve], error) {
	buf := make([]byte, scalarByteSize)
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
	bi := new(big.Int).SetBytes(h[:])
	bi.Mod(bi, generatorOrder)
	le := littleEndian(bi)
	var v edwards25519.Scalar
	_, err := v.SetCanonicalBytes(le)
	if err != nil {
		panic(err)
	}
	return makeScalar(&v)
}

func (c Curve) EncodeToPoint(data []byte) (curve.Point[Curve], error) {
	return c.encoder.EncodeToPoint(data)
}

func (c Curve) DecodeFromPoint(p curve.Point[Curve]) []byte {
	return c.encoder.DecodeFromPoint(p)
}
