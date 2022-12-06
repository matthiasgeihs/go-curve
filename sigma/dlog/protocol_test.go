package dlog_test

import (
	"crypto/rand"
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
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

	t.Run("extract", func(t *testing.T) {
		p := dlog.NewProver[C](g, rnd, w)
		v := dlog.NewVerifier[C](g, rnd, word)
		e := dlog.NewExtractor(g)
		check := func(w dlog.Witness[C]) bool {
			gw := g.Generator().Mul(w)
			return word.X().Cmp(gw.X()) == 0
		}
		extract(t, p, v, e, check)
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

func extract[C curve.Curve](
	t *testing.T,
	p dlog.Prover[C],
	v dlog.Verifier[C],
	ext dlog.Extractor[C],
	relation func(dlog.Witness[C]) bool,
) {
	com, decom, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}

	// Challenge-response 1.
	ch1, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}
	resp1 := p.Respond(decom, ch1)
	t1 := sigma.MakeTranscript(ch1, resp1)

	// Challenge-response 2.
	ch2, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}
	resp2 := p.Respond(decom, ch2)
	t2 := sigma.MakeTranscript(ch2, resp2)

	w := ext.Extract(t1, t2).(dlog.Witness[C])
	if !relation(w) {
		t.Fatal("not a witness")
	}
}
