package curve

import (
	"fmt"
	"math/big"
)

const idxMessageLength = 0
const idxMessageStart = 1

type MakePoint[C Curve] func(*big.Int) (Point[C], error)

type Encoder[C Curve] struct {
	fieldSize     uint
	fieldOrder    *big.Int
	messageLength uint
	makePoint     MakePoint[C]
}

func NewEncoder[C Curve](
	fieldSize uint,
	fieldOrder *big.Int,
	messageLength uint,
	makePoint MakePoint[C],
) Encoder[C] {
	return Encoder[C]{
		fieldSize:     fieldSize,
		fieldOrder:    new(big.Int).Set(fieldOrder),
		messageLength: messageLength,
		makePoint:     makePoint,
	}
}

func (e Encoder[C]) idxMsgEnd() uint {
	return idxMessageStart + e.messageLength
}

func (e Encoder[C]) EncodeToPoint(data []byte) (Point[C], error) {
	if uint(len(data)) > e.messageLength {
		return nil, fmt.Errorf("data exceeds message space")
	}

	m := make([]byte, e.fieldSize) // len(data) || data || counter
	m[idxMessageLength] = safeCastIntToByte(len(data))
	idxMsgEnd := e.idxMsgEnd()
	copy(m[1:idxMsgEnd], data)

	counter := big.NewInt(0)
	mi := new(big.Int)
	var p Point[C]
	var err error
	for {
		copy(m[idxMsgEnd:], counter.Bytes())
		mi.SetBytes(m[:])
		p, err = e.makePoint(mi)
		if err == nil {
			break
		} else if mi.Cmp(e.fieldOrder) >= 0 {
			return nil, fmt.Errorf("integer encoding exceeds field bounds")
		}
		counter.Add(counter, big.NewInt(1))
	}

	return p, nil
}

func (e Encoder[C]) DecodeFromPoint(p Point[C]) []byte {
	buf := p.X().Bytes()
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
