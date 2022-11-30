package ecdsa

import (
	"fmt"
	"io"
	"math/big"

	"github.com/matthiasgeihs/go-curve/curve"
)

type SecretKey[P curve.Curve] curve.Scalar[P]
type PubKey[P curve.Curve] curve.Point[P]
type Sig[P curve.Curve] struct {
	r curve.Scalar[P]
	s curve.Scalar[P]
}

type ECDSA[C curve.Curve] struct {
	gen curve.Generator[C]
	rnd io.Reader
}

func NewECDSA[C curve.Curve](gen curve.Generator[C], rnd io.Reader) ECDSA[C] {
	return ECDSA[C]{
		gen: gen,
		rnd: rnd,
	}
}

func (dsa *ECDSA[C]) KeyGen() (SecretKey[C], PubKey[C], error) {
	sk, err := dsa.gen.RandomScalar(dsa.rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("generating secret key: %w", err)
	}
	pk := dsa.gen.Generator().Mul(sk)
	return sk, pk, nil
}

func (dsa *ECDSA[C]) Sign(sk SecretKey[C], m []byte) (Sig[C], error) {
	var k, r curve.Scalar[C]
	for {
		var err error
		k, err = dsa.gen.RandomScalar(dsa.rnd)
		if err != nil {
			return Sig[C]{}, fmt.Errorf("generating nonce: %w", err)
		}
		gk := dsa.gen.Generator().Mul(k)
		r = dsa.gen.NewScalar(gk.X())

		zero := dsa.gen.NewScalar(big.NewInt(0))
		if !r.Equal(zero) {
			break
		}
	}

	z := dsa.gen.HashToScalar(m)
	rsk := r.Mul(sk)
	zrsk := z.Add(rsk)
	s := k.Inv().Mul(zrsk)
	return Sig[C]{
		r: r,
		s: s,
	}, nil
}

func (dsa *ECDSA[C]) Verify(pk PubKey[C], m []byte, sig Sig[C]) bool {
	z := dsa.gen.HashToScalar(m)
	sinv := sig.s.Inv()
	u1 := z.Mul(sinv)
	u2 := sig.r.Mul(sinv)

	gu1 := dsa.gen.Generator().Mul(u1)
	pku2 := pk.Mul(u2)
	gu1pku2 := gu1.Add(pku2)
	gu1pku2x := dsa.gen.NewScalar(gu1pku2.X())
	return sig.r.Equal(gu1pku2x)
}
