package enc

import (
	"fmt"
	"io"
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
)

type Cipher[C curve.Curve] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

type SecretKey[C curve.Curve] curve.Scalar[C]
type PubKey[C curve.Curve] curve.Point[C]
type Ciphertext[C curve.Curve] struct {
	c1, c2 curve.Point[C]
}

func NewCipher[C curve.Curve](gen curve.Generator[C], rnd io.Reader) Cipher[C] {
	return Cipher[C]{
		gen: gen,
		rnd: rnd,
	}
}

func (enc *Cipher[C]) KeyGen() (SecretKey[C], PubKey[C], error) {
	sk, err := enc.gen.RandomScalar(enc.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("generating secret key: %w", err)
	}
	pk := enc.gen.Generator().Mul(sk)
	return sk, pk, nil
}

func (enc *Cipher[C]) Encrypt(pk PubKey[C], data []byte) (Ciphertext[C], error) {
	m, err := enc.gen.EncodeToPoint(data)
	if err != nil {
		return Ciphertext[C]{}, fmt.Errorf("encoding data to point: %w", err)
	}

	y, err := enc.gen.RandomScalar(enc.rnd)
	if err != nil {
		return Ciphertext[C]{}, fmt.Errorf("generating nonce: %w", err)
	}

	s := pk.Mul(y)
	return Ciphertext[C]{
		c1: enc.gen.Generator().Mul(y),
		c2: m.Add(s),
	}, nil
}

func (ciph *Cipher[C]) Decrypt(sk SecretKey[C], ct Ciphertext[C]) []byte {
	qSubSk := new(big.Int).Sub(ciph.gen.GeneratorOrder(), sk.Int())
	qSubSkScalar := ciph.gen.NewScalar(qSubSk)
	sinv := ct.c1.Mul(qSubSkScalar)
	m := ct.c2.Add(sinv)
	return ciph.gen.DecodeFromPoint(m)
}
