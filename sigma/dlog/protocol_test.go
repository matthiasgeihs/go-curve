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

var _ sigma.Prover[secp256k1.Curve, dlog.Protocol] = dlog.Prover[secp256k1.Curve, dlog.Protocol]{}
var _ sigma.Verifier[secp256k1.Curve, dlog.Protocol] = dlog.Verifier[secp256k1.Curve, dlog.Protocol]{}
var _ sigma.Extractor[secp256k1.Curve, dlog.Protocol] = dlog.Extractor[secp256k1.Curve, dlog.Protocol]{}

func TestProtocol_secp256k1(t *testing.T) {
	g := secp256k1.NewGenerator()
	testProtocol[secp256k1.Curve, dlog.Protocol](t, g)
}

func TestProtocol_edwards25519(t *testing.T) {
	g := edwards25519.NewGenerator()
	testProtocol[edwards25519.Curve, dlog.Protocol](t, g)
}

func testProtocol[C curve.Curve, P sigma.Protocol](t *testing.T, g curve.Generator[C]) {
	rnd := rand.Reader
	w, err := g.RandomScalar(rnd)
	if err != nil {
		panic(err)
	}
	x := g.Generator().Mul(w)

	t.Run("honest", func(t *testing.T) {
		p := dlog.NewProver[C, P](g, rnd)
		v := dlog.NewVerifier[C, P](g, rnd)
		valid := runProtocol[C, P](t, p, v, x, w)
		if !valid {
			t.Error("proof should be valid")
		}
	})

	t.Run("malicious", func(t *testing.T) {
		// Generate different witness.
		w, err := g.RandomScalar(rnd)
		if err != nil {
			panic(err)
		}
		p := dlog.NewProver[C, P](g, rnd)
		v := dlog.NewVerifier[C, P](g, rnd)
		valid := runProtocol[C, P](t, p, v, x, w)
		if valid {
			t.Error("proof should be invalid")
		}
	})

	t.Run("extract", func(t *testing.T) {
		p := dlog.NewProver[C, P](g, rnd)
		v := dlog.NewVerifier[C, P](g, rnd)
		e := dlog.NewExtractor[C, P](g)
		check := func(w dlog.Witness[C]) bool {
			gw := g.Generator().Mul(w)
			return x.X().Cmp(gw.X()) == 0
		}
		extract[C, P](t, p, v, e, check, x, w)
	})

	t.Run("encoder", func(t *testing.T) {
		encoder := dlog.NewEncoder[C, P](g)
		s, err := g.RandomScalar(rnd)
		if err != nil {
			panic(err)
		}
		resp := dlog.Response[C](s)
		data := encoder.EncodeResponse(resp)
		respDecoded := encoder.DecodeResponse(data)

		eq := resp.Equal(respDecoded.(dlog.Response[C]))
		if !eq {
			t.Error("response should decode to the same value")
		}
	})
}

func runProtocol[C curve.Curve, P sigma.Protocol](
	t *testing.T,
	p sigma.Prover[C, P],
	v sigma.Verifier[C, P],
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
) bool {
	com, decom, err := p.Commit(x, w)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}

	resp := p.Respond(x, w, decom, ch)
	return v.Verify(x, com, ch, resp)
}

func extract[C curve.Curve, P sigma.Protocol](
	t *testing.T,
	p sigma.Prover[C, P],
	v sigma.Verifier[C, P],
	ext dlog.Extractor[C, P],
	relation func(dlog.Witness[C]) bool,
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
) {
	com, decom, err := p.Commit(x, w)
	if err != nil {
		t.Fatal(err)
	}

	// Challenge-response 1.
	ch1, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}
	resp1 := p.Respond(x, w, decom, ch1)
	t1 := sigma.MakeTranscript(ch1, resp1)

	// Challenge-response 2.
	ch2, err := v.Challenge(com)
	if err != nil {
		t.Fatal(err)
	}
	resp2 := p.Respond(x, w, decom, ch2)
	t2 := sigma.MakeTranscript(ch2, resp2)

	wExt := ext.Extract(t1, t2).(dlog.Witness[C])
	if !relation(wExt) {
		t.Fatal("not a witness")
	}
}
