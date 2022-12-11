package cd00_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
	"github.com/matthiasgeihs/go-curve/verenc/cd00"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc/rsa"
)

const secLevel = 64

func TestProtocol_secp256k1(t *testing.T) {
	type C = secp256k1.Curve
	type P = dlog.Protocol
	type E = rsa.Scheme
	rnd := rand.Reader
	g := secp256k1.NewGenerator()
	enc, dec, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}
	setupAndRun[C, P](t, rnd, g, enc, dec)
}

func TestProtocol_edwards25519(t *testing.T) {
	type C = edwards25519.Curve
	type P = dlog.Protocol
	type E = rsa.Scheme
	rnd := rand.Reader
	g := edwards25519.NewGenerator()
	enc, dec, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}
	setupAndRun[C, P](t, rnd, g, enc, dec)
}

func setupAndRun[C curve.Curve, P sigma.Protocol, E probenc.Scheme](
	t *testing.T,
	rnd io.Reader,
	g curve.Generator[C],
	encrypter probenc.Encrypter[E],
	decrypter probenc.Decrypter[E],
) {
	sigmaP := dlog.NewProver[C, P](g, rnd)
	sigmaV := dlog.NewVerifier[C, P](g, rnd)
	sigmaExt := dlog.NewExtractor[C, P](g)
	sigmaEnc := dlog.NewEncoder[C, P](g)

	p := cd00.NewProver[C, P](sigmaP, sigmaV, sigmaEnc, encrypter, rnd)
	v := cd00.NewVerifier[C, P](rnd, sigmaV, sigmaEnc, encrypter)
	d := cd00.NewDecrypter[C, P](sigmaV, sigmaExt, sigmaEnc, decrypter)

	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	x := g.Generator().Mul(w)
	runProtocol[C, P](
		t, p, v, d, x, w,
		sigmaEnc,
		secLevel,
	)
}

func runProtocol[C curve.Curve, P sigma.Protocol, E probenc.Scheme](
	t *testing.T,
	p cd00.Prover[C, P, E],
	v cd00.Verifier[C, P, E],
	d cd00.Decrypter[C, P, E],
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	encoder sigma.Encoder[C, P],
	securityLevel uint,
) {
	// Run protocol repeatedly to increase chance of catching cheating prover.
	ct := make([]cd00.Ciphertext[C, P, E], securityLevel)
	for i := uint(0); i < securityLevel; i++ {
		com, decom, err := p.Commit(x, w)
		if err != nil {
			t.Fatal(err)
		}

		ch := v.Challenge(com)
		if err != nil {
			t.Fatal(err)
		}

		resp := p.Respond(decom, ch)
		ct[i], err = v.Verify(x, com, ch, resp)
		if err != nil {
			t.Error(err)
		}
	}

	// Decrypt.
	wDec := func() sigma.Witness[C, P] {
		for _, cti := range ct {
			wDec, err := d.Decrypt(cti, x)
			if err == nil {
				return wDec
			}
		}
		t.Fatal("should decrypt")
		return nil
	}()

	// Check correct decryption.
	wBytes := encoder.EncodeWitness(w)
	wDecBytes := encoder.EncodeWitness(wDec)
	if !bytes.Equal(wBytes, wDecBytes) {
		t.Error("decrypted value should match encrypted value")
	}
}
