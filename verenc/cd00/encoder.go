package cd00

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type sigmaEncoder[G curve.Curve, P sigma.Protocol] interface {
	sigma.Encoder[G, P]
}

type Encoder[G curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	sigmaEncoder[G, P]
}

func newEncoder[G curve.Curve, P sigma.Protocol, E probenc.Scheme](sigmaE sigma.Encoder[G, P]) *Encoder[G, P, E] {
	return &Encoder[G, P, E]{
		sigmaEncoder: sigmaE,
	}
}

func (e *Encoder[G, P, E]) EncodeEncryptedResponses(resps []EncryptedResponse[G, P, E]) ([]byte, error) {
	var buf bytes.Buffer

	// Write length.
	err := binary.Write(&buf, binary.BigEndian, int64(len(resps)))
	if err != nil {
		return nil, fmt.Errorf("writing length: %w", err)
	}

	// Write elements.
	for i, r := range resps {
		// Write commitment.
		commBytes, err := e.EncodeCommitment(r.t)
		if err != nil {
			return nil, fmt.Errorf("encoding commitment %d: %w", i, err)
		}
		err = binary.Write(&buf, binary.BigEndian, commBytes)
		if err != nil {
			return nil, fmt.Errorf("writing commitment %d: %w", i, err)
		}

		// Write encryption.
		err = binary.Write(&buf, binary.BigEndian, r.e)
		if err != nil {
			return nil, fmt.Errorf("writing ciphertext %d: %w", i, err)
		}
	}

	return buf.Bytes(), nil
}
