package cd00_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/matthiasgeihs/go-curve/commit"
	"github.com/matthiasgeihs/go-curve/commit/sha256"
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	dlog "github.com/matthiasgeihs/go-curve/sigma/dlog/binary"
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
	type C = sha256.Scheme
	rnd := rand.Reader
	g := secp256k1.NewGenerator()
	p := dlog.NewProver[G](g, rnd)
	v := dlog.NewVerifier[G](g, rnd)
	commC := sha256.NewCommitter(rnd)
	commV := sha256.NewVerifier()
	ext := dlog.NewExtractor[G](g)
	encoder := dlog.NewEncoder[G](g)
	encrypter, decrypter, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}
	setupAndRun[G, P, E, C](t, rnd, g, commC, commV, p, v, ext, encoder, encrypter, decrypter)
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
	p := cd00.NewProver(K, sigmaP, sigmaV, sigmaEnc, encrypter, commC, rnd)
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
	)
}

func runProtocol[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme](
	t *testing.T,
	p *cd00.Prover[G, P, E, C],
	v *cd00.Verifier[G, P, E, C],
	d *cd00.Decrypter[G, P, E],
	x sigma.Word[G, P],
	w sigma.Witness[G, P],
	encoder sigma.Encoder[G, P],
) {
	com, decom, err := p.Commit(x, w)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}

	resp := p.Respond(decom, ch)

	ct, err := v.Verify(x, com, ch, resp)
	if err != nil {
		t.Fatal(err)
	}

	wDec, err := d.Decrypt(ct, x)
	if err != nil {
		t.Fatal(err)
	}

	// Check correct decryption.
	wBytes := encoder.EncodeWitness(w)
	wDecBytes := encoder.EncodeWitness(wDec)
	if !bytes.Equal(wBytes, wDecBytes) {
		t.Error("decryption should equal encryption")
	}
}
