package secp256k1

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/matthiasgeihs/go-curve/curve"
)

type Curve struct{}

// Check that type implements interface.
var _ curve.Generator[Curve] = Curve{}

func NewGenerator() Curve {
	return Curve{}
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

const fieldSize = 32
const maxMessageLength = fieldSize / 2
const idxMessageLength = 0
const idxMessageStart = 1
const idxMsgEnd = idxMessageStart + maxMessageLength

func (Curve) EncodeToPoint(data []byte) (curve.Point[Curve], error) {
	if len(data) > maxMessageLength {
		return nil, fmt.Errorf("data exceeds message space")
	}

	var m [fieldSize]byte // len(data) || data || counter
	m[idxMessageLength] = safeCastIntToByte(len(data))
	copy(m[1:idxMsgEnd], data)

	counter := big.NewInt(0)
	mi := new(big.Int)
	var p Point
	var err error
	for {
		copy(m[idxMsgEnd:], counter.Bytes())
		mi.SetBytes(m[:])
		p, err = makePointFromAffineX(mi)
		if err == nil {
			break
		} else if mi.Cmp(secp.Params().P) >= 0 {
			return nil, fmt.Errorf("integer encoding exceeds field bounds")
		}
		counter.Add(counter, big.NewInt(1))
	}

	return p, nil
}

func (Curve) DecodeFromPoint(p curve.Point[Curve]) []byte {
	pPoint := p.(Point).p
	pPoint.ToAffine()
	buf := pPoint.X.Bytes()
	l := buf[idxMessageLength]
	data := make([]byte, l)
	copy(data, buf[idxMessageStart:])
	return data
}

func safeCastIntToByte(i int) byte {
	const maxByteVal = 1<<8 - 1
	if i > maxByteVal {
		panic("input exceeds max byte value")
	}
	return byte(i)
}
