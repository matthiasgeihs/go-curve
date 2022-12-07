package cd00_test

import (
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00"
)

func runProtocol[C curve.Curve, P sigma.Protocol[C]](
	t *testing.T,
	p cd00.Prover[C, P],
	v cd00.Verifier[C, P],
	d cd00.Decrypter[C, P],
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
) {
	com, decom, err := p.Commit(x, w, E)
	if err != nil {
		t.Fatal(err)
	}

	ch, err := v.Challenge(x, E)
	if err != nil {
		t.Fatal(err)
	}

	resp := p.Respond(decom, ch)
	ct, err := v.Verify(com, ch, resp)
	if err != nil {
		t.Fatal(err)
	}

	wDec, err := d.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	} else if w != wDec {
		t.Error(err)
	}
}
