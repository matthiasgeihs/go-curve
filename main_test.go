package main_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"testing"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

// Upper bound for big integer tests.
var UB = new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)

func BenchmarkInplace(b *testing.B) {
	rnd := rand.New(rand.NewSource(0))
	a := big.NewInt(0)
	for i := 0; i < b.N; i++ {
		b := new(big.Int).Rand(rnd, UB)
		a.Add(a, b)
		a.Mod(a, UB)
	}
	b.Log(a)
}

func BenchmarkReplace(b *testing.B) {
	rnd := rand.New(rand.NewSource(0))
	a := big.NewInt(0)
	for i := 0; i < b.N; i++ {
		b := new(big.Int).Rand(rnd, UB)
		a = new(big.Int).Add(a, b)
		a = new(big.Int).Mod(a, UB)
	}
	b.Log(a)
}

func TestECDSA_edwards25519_native(t *testing.T) {
	rnd := crand.Reader
	sk, pk, err := KeyGen(rnd)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Hello, Singapore!")
	sig, err := Sign(rnd, sk, msg)
	if err != nil {
		t.Fatal(err)
	}

	valid := Verify(pk, msg, sig)
	if !valid {
		t.Error("Signature invalid")
	}
}

func KeyGen(rnd io.Reader) (*edwards25519.Scalar, *edwards25519.Point, error) {
	sk, err := RandomScalar(rnd)
	if err != nil {
		return nil, nil, fmt.Errorf("generating secret key: %w", err)
	}
	pk := new(edwards25519.Point).ScalarBaseMult(sk)
	return sk, pk, nil
}

var generatorOrder, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)

const scalarByteSize = 32

func RandomScalar(rnd io.Reader) (*edwards25519.Scalar, error) {
	buf := make([]byte, scalarByteSize)
	_, err := rnd.Read(buf)
	if err != nil {
		return nil, err
	}
	rbi := new(big.Int).SetBytes(buf)
	return makeScalarFromBigInt(rbi), nil
}

func makeScalarFromBigInt(v *big.Int) *edwards25519.Scalar {
	vMod := new(big.Int).Mod(v, generatorOrder)
	b := littleEndian(vMod)
	buf := make([]byte, scalarByteSize)
	copy(buf, b)
	vScalar, err := edwards25519.NewScalar().SetCanonicalBytes(buf)
	if err != nil {
		panic(err)
	}

	return vScalar
}

func littleEndian(v *big.Int) []byte {
	b := v.Bytes()
	reverse(b)
	return b
}

// Reverse slice in-place.
func reverse[T any](b []T) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

type Sig struct {
	r, s *edwards25519.Scalar
}

func Sign(rnd io.Reader, sk *edwards25519.Scalar, m []byte) (Sig, error) {
	var k, r *edwards25519.Scalar
	for {
		var err error
		k, err = RandomScalar(rnd)
		if err != nil {
			return Sig{}, fmt.Errorf("generating nonce: %w", err)
		}
		gk := new(edwards25519.Point).ScalarBaseMult(k)
		gkx := xFromPoint(gk)
		r = makeScalarFromBigInt(gkx)

		zero := makeScalarFromBigInt(big.NewInt(0))
		if r.Equal(zero) == 0 {
			break
		}
	}

	z := HashToScalar(m)
	rsk := new(edwards25519.Scalar).Multiply(r, sk)
	zrsk := new(edwards25519.Scalar).Add(z, rsk)
	kinv := new(edwards25519.Scalar).Invert(k)
	s := new(edwards25519.Scalar).Multiply(kinv, zrsk)
	return Sig{
		r: r,
		s: s,
	}, nil
}

func xFromPoint(p *edwards25519.Point) *big.Int {
	x, _, z, _ := p.ExtendedCoordinates()
	zinv := new(field.Element).Invert(z)
	ax := new(field.Element).Multiply(x, zinv)
	b := ax.Bytes()
	reverse(b)
	return new(big.Int).SetBytes(b)
}

func HashToScalar(data []byte) *edwards25519.Scalar {
	h := sha256.Sum256(data)
	bi := new(big.Int).SetBytes(h[:])
	bi.Mod(bi, generatorOrder)
	le := littleEndian(bi)
	v, err := new(edwards25519.Scalar).SetCanonicalBytes(le)
	if err != nil {
		panic(err)
	}
	return v
}

func Verify(pk *edwards25519.Point, m []byte, sig Sig) bool {
	z := HashToScalar(m)
	sinv := new(edwards25519.Scalar).Invert(sig.s)
	u1 := new(edwards25519.Scalar).Multiply(z, sinv)
	u2 := new(edwards25519.Scalar).Multiply(sig.r, sinv)

	gu1 := new(edwards25519.Point).ScalarBaseMult(u1)
	pku2 := new(edwards25519.Point).ScalarMult(u2, pk)
	gu1pku2 := new(edwards25519.Point).Add(gu1, pku2)

	gu1pku2x := xFromPoint(gu1pku2)
	gu1pku2x.Mod(gu1pku2x, generatorOrder)
	rint := intFromScalar(sig.r)
	b := rint.Cmp(gu1pku2x) == 0
	return b
}

func intFromScalar(s *edwards25519.Scalar) *big.Int {
	b := s.Bytes()
	reverse(b)
	return new(big.Int).SetBytes(b[:])
}
