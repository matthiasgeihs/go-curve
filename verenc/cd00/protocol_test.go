package cd00_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/matthiasgeihs/go-curve/commit"
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
	"github.com/matthiasgeihs/go-curve/verenc/cd00"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc/rsa"
)

const K = 712
const U = 20

func TestProtocol_secp256k1(t *testing.T) {
	type G = secp256k1.Curve
	type P = dlog.Protocol
	type E = rsa.Scheme
	rnd := rand.Reader
	g := secp256k1.NewGenerator()
	p := dlog.NewProver[G](g, rnd)
	v := dlog.NewVerifier[G](g, rnd)
	ext := dlog.NewExtractor[G](g)
	encoder := dlog.NewEncoder[G](g)
	encrypter, decrypter, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}
	setupAndRun[G, P, E](t, rnd, g, commC, commV, p, v, ext, encoder, encrypter, decrypter)
}

func setupAndRun[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme](
	t *testing.T,
	rnd io.Reader,
	g curve.Generator[G],
	commC commit.Committer[C],
	commV commit.Verifier[C],
	sigmaP sigma.Prover[G, P],
	sigmaV sigma.Verifier[G, P],
	sigmaExt sigma.Extractor[G, P],
	sigmaEnc sigma.Encoder[G, P],
	encrypter probenc.Encrypter[E],
	decrypter probenc.Decrypter[E],
) {
	p := cd00.NewProver(sigmaP, sigmaV, sigmaEnc, encrypter, commC, rnd)
	v := cd00.NewVerifier(rnd, K, U, commV, sigmaV, sigmaEnc, encrypter)
	d := cd00.NewDecrypter(sigmaV, sigmaExt, sigmaEnc, decrypter)

	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	x := g.Generator().Mul(w)
	runProtocol[G, P](
		t, p, v, d, x, w,
		sigmaEnc,
		secLevel,
	)
}
