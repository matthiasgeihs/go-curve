package cd00_test

import (
	"bytes"
	"crypto/rand"
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
	g := secp256k1.NewGenerator()
	setupAndRun[C, P](t, g)
}

func TestProtocol_edwards25519(t *testing.T) {
	type C = edwards25519.Curve
	type P = dlog.Protocol
	g := edwards25519.NewGenerator()
	setupAndRun[C, P](t, g)
}

func setupAndRun[C curve.Curve, P sigma.Protocol](
	t *testing.T,
	g curve.Generator[C],
) {
	rnd := rand.Reader
	sigmaP := dlog.NewProver[C, P](g, rnd)
	sigmaV := dlog.NewVerifier[C, P](g, rnd)
	sigmaExt := dlog.NewExtractor[C, P](g)
	sigmaEnc := dlog.NewEncoder[C, P](g)
	encrypt, decrypt, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}

	p := cd00.NewProver[C, P](sigmaP, sigmaV, sigmaEnc, rnd)
	v := cd00.NewVerifier[C, P](rnd, sigmaV, sigmaEnc)
	d := cd00.NewDecrypter[C, P](sigmaV, sigmaExt, sigmaEnc)

	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	x := g.Generator().Mul(w)
	runProtocol[C, P](t, p, v, d, x, w, encrypt, decrypt, sigmaEnc, secLevel)
}

func runProtocol[C curve.Curve, P sigma.Protocol](
	t *testing.T,
	p cd00.Prover[C, P],
	v cd00.Verifier[C, P],
	d cd00.Decrypter[C, P],
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	enc probenc.Encrypt,
	dec probenc.Decrypt,
	encoder sigma.Encoder[C, P],
	securityLevel uint,
) {
	// Run protocol repeatedly to increase chance of catching cheating prover.
	ct := make([]cd00.Ciphertext[C, P], securityLevel)
	for i := uint(0); i < securityLevel; i++ {
		com, decom, err := p.Commit(x, w, enc)
		if err != nil {
			t.Fatal(err)
		}

		ch := v.Challenge(com)
		if err != nil {
			t.Fatal(err)
		}

		resp := p.Respond(decom, ch)
		ct[i], err = v.Verify(x, com, ch, resp, enc)
		if err != nil {
			t.Error(err)
		}
	}

	// Decrypt.
	wDec := func() sigma.Witness[C, P] {
		for _, cti := range ct {
			wDec, err := d.Decrypt(cti, x, dec)
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
