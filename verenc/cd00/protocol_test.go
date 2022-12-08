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
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc/rsa"
)

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
	encrypt, verifyEncrypt, decrypt, err := rsa.NewInstace(rnd, 2048)
	if err != nil {
		panic(err)
	}

	p := cd00.NewProver[C, P](sigmaP, sigmaV, sigmaEnc)
	v := cd00.NewVerifier[C, P](rnd, sigmaV, sigmaEnc)
	d := cd00.NewDecrypter[C, P](sigmaExt, sigmaEnc)

	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	x := g.Generator().Mul(w)
	runProtocol[C, P](t, p, v, d, x, w, encrypt, verifyEncrypt, decrypt, sigmaEnc)
}

func runProtocol[C curve.Curve, P sigma.Protocol](
	t *testing.T,
	p cd00.Prover[C, P],
	v cd00.Verifier[C, P],
	d cd00.Decrypter[C, P],
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	enc enc.Encrypt,
	verEnc enc.VerifyEncrypt,
	dec enc.Decrypt,
	encoder sigma.Encoder[C, P],
) {
	com, decom, err := p.Commit(x, w, enc)
	if err != nil {
		t.Fatal(err)
	}

	ch := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}

	resp := p.Respond(decom, ch)
	ct, err := v.Verify(x, com, ch, resp, verEnc)
	if err != nil {
		t.Fatal(err)
	}

	wDec, err := d.Decrypt(ct, dec)
	if err != nil {
		t.Fatal(err)
	}

	wBytes := encoder.EncodeWitness(w)
	wDecBytes := encoder.EncodeWitness(wDec)
	if !bytes.Equal(wBytes, wDecBytes) {
		t.Error("decrypted value should match encrypted value")
	}
}
