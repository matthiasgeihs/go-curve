package binary

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func (e Encoder[C]) EncodeCommitment(comm sigma.Commitment[C, Protocol]) ([]byte, error) {
	dlogComm := comm.(dlog.Commitment[C])
	var buf bytes.Buffer

	// Encode X.
	err := writeBigInt(&buf, dlogComm.X())
	if err != nil {
		return nil, fmt.Errorf("encoding X: %w", err)
	}

	// Encode Y.
	err = writeBigInt(&buf, dlogComm.Y())
	if err != nil {
		return nil, fmt.Errorf("encoding Y: %w", err)
	}

	return buf.Bytes(), nil
}

func (e Encoder[C]) DecodeCommitment(data []byte) (sigma.Commitment[C, Protocol], error) {
	buf := bytes.NewBuffer(data)

	// Decode X.
	x, err := readBigInt(buf)
	if err != nil {
		return nil, fmt.Errorf("decoding X: %w", err)
	}

	// Decode Y.
	y, err := readBigInt(buf)
	if err != nil {
		return nil, fmt.Errorf("decoding Y: %w", err)
	}

	return e.gen.NewPoint(x, y), nil
}

func writeBigInt(buf *bytes.Buffer, i *big.Int) error {
	b, err := i.GobEncode()
	if err != nil {
		return fmt.Errorf("encoding big int to bytes: %w", err)
	}
	err = binary.Write(buf, binary.BigEndian, b)
	if err != nil {
		return fmt.Errorf("encoding byte slice: %w", err)
	}
	return nil
}

func readBigInt(buf *bytes.Buffer) (*big.Int, error) {
	var b []byte
	err := binary.Read(buf, binary.BigEndian, &b)
	if err != nil {
		return nil, fmt.Errorf("decoding byte slice: %w", err)
	}

	i := new(big.Int)
	err = i.GobDecode(b)
	if err != nil {
		return nil, fmt.Errorf("decoding big int from bytes: %w", err)
	}
	return i, nil
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
