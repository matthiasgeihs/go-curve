package cd00

import (
	"bytes"
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Prover[C curve.Curve, P sigma.Protocol] struct {
	sigmaP  sigma.Prover[C, P]
	sigmaV  sigma.Verifier[C, P]
	encoder sigma.Encoder[C, P]
	rnd     io.Reader
}
type Commitment[C curve.Curve, P sigma.Protocol] struct {
	t  sigma.Commitment[C, P]
	ch [2]sigma.Challenge[C, P]
	e  [2]probenc.Ciphertext
}
type Decommitment[C curve.Curve, P sigma.Protocol] struct {
	r [2]RandomBytes
	s [2]sigma.Response[C, P]
}
type Response[C curve.Curve, P sigma.Protocol] struct {
	r RandomBytes
	s sigma.Response[C, P]
}

func NewProver[C curve.Curve, P sigma.Protocol](
	p sigma.Prover[C, P],
	v sigma.Verifier[C, P],
	encoder sigma.Encoder[C, P],
	rnd io.Reader,
) Prover[C, P] {
	return Prover[C, P]{
		sigmaP:  p,
		sigmaV:  v,
		encoder: encoder,
		rnd:     rnd,
	}
}

func (p Prover[C, P]) Commit(
	x sigma.Word[C, P],
	w sigma.Witness[C, P],
	enc probenc.Encrypt,
) (
	Commitment[C, P],
	Decommitment[C, P],
	error,
) {
	t, rt, err := p.sigmaP.Commit(x, w)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol commit: %w", err)
	}

	ch0, err := p.sigmaV.Challenge(t)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol challenge 1: %w", err)
	}
	ch1, err := p.sigmaV.Challenge(t)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("sigma protocol challenge 2: %w", err)
	}
	s0, s1 := p.sigmaP.Respond(x, w, rt, ch0), p.sigmaP.Respond(x, w, rt, ch1)
	s0Bytes, s1Bytes := p.encoder.EncodeResponse(s0), p.encoder.EncodeResponse(s1)
	e0, r0, err := encrypt(p.rnd, s0Bytes, enc)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("encrypting s0: %w", err)
	}
	e1, r1, err := encrypt(p.rnd, s1Bytes, enc)
	if err != nil {
		return Commitment[C, P]{}, Decommitment[C, P]{}, fmt.Errorf("encrypting s1: %w", err)
	}

	com := Commitment[C, P]{
		t,
		[2]sigma.Challenge[C, P]{ch0, ch1},
		[2]probenc.Ciphertext{e0, e1},
	}
	decom := Decommitment[C, P]{
		[2]RandomBytes{r0, r1},
		[2]sigma.Response[C, P]{s0, s1},
	}
	return com, decom, nil
}

type RandomBytes []byte

// encrypt encrypts `data` using the probabilistic encryption algorithm `enc`
// using `rnd` as source of randomness. It returns the ciphertext and the bytes
// consumed from `rnd`.
func encrypt(
	rnd io.Reader,
	data []byte,
	enc probenc.Encrypt,
) (probenc.Ciphertext, RandomBytes, error) {
	var buf bytes.Buffer
	rndExt := io.TeeReader(rnd, &buf)
	ct, err := enc(rndExt, data)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting data: %w", err)
	}
	r := buf.Bytes()
	return ct, r, nil
}

func (p Prover[C, P]) Respond(
	decom Decommitment[C, P],
	ch Challenge,
) Response[C, P] {
	chi := chtoi(ch)
	return Response[C, P]{decom.r[chi], decom.s[chi]}
}

func chtoi(ch Challenge) int {
	if ch {
		return 1
	}
	return 0
}
