package dlog_test

import (
	"crypto/rand"
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	"github.com/matthiasgeihs/go-curve/sigma/schnorr/dlog"
)

func TestProtocol_secp256k1(t *testing.T) {
	g := secp256k1.NewGenerator()
	testProtocol[secp256k1.Curve](t, g)
}

func TestProtocol_edwards25519(t *testing.T) {
	g := edwards25519.NewGenerator()
	testProtocol[edwards25519.Curve](t, g)
}

func testProtocol[C curve.Curve](t *testing.T, g curve.Generator[C]) {
	rnd := rand.Reader
	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	word := g.Generator().Mul(w)

	t.Run("honest", func(t *testing.T) {
		p := dlog.NewProver[C](g, rnd, w)
		v := dlog.NewVerifier[C](g, rnd, word)
		err = runProtocol(t, p, v)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("malicious", func(t *testing.T) {
		// Generate different witness.
		w, err := g.RandomScalar(rnd)
		if err != nil {
			panic(err)
		}
		p := dlog.NewProver[C](g, rnd, w)
		v := dlog.NewVerifier[C](g, rnd, word)
		err = runProtocol(t, p, v)
		if err == nil {
			t.Fatal("verification should fail")
		}
	})
}

func runProtocol[C curve.Curve](t *testing.T, p dlog.Prover[C], v dlog.Verifier[C]) error {
	com, decom, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}

	resp := p.Respond(decom, ch)
	return v.Verify(com, ch, resp)
}
