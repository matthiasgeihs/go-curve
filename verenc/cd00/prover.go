package cd00

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/commit"
	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Prover[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	sigmaP    sigma.Prover[G, P]
	sigmaV    sigma.Verifier[G, P]
	encoder   *encoder[G, P, E]
	encrypter probenc.Encrypter[E]
	committer commit.Committer[C]
	rnd       io.Reader
	k         uint
}

type Commitment[C commit.Scheme] commit.Commitment[C]

type Decommitment[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	x       sigma.Word[G, P]
	w       sigma.Witness[G, P]
	decomms []sigma.Decommitment[C, P]
	s       []EncryptedResponse[G, P, E]
	r       []probenc.RandomBytes
	decom   commit.Decommitment[C]
}

type Challenge []uint

type Response[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	encResps []EncryptedResponse[G, P, E]
	d        commit.Decommitment[C]
	s        []sigma.Response[G, P]
	r        []probenc.RandomBytes
}

type EncryptedResponse[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	t sigma.Commitment[C, P]
	e probenc.Ciphertext[E]
}

func NewProver[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme](
	p sigma.Prover[G, P],
	v sigma.Verifier[G, P],
	encoder sigma.Encoder[G, P],
	encrypter probenc.Encrypter[E],
	committer commit.Committer[C],
	rnd io.Reader,
) Prover[G, P, E, C] {
	return Prover[G, P, E, C]{
		sigmaP:    p,
		sigmaV:    v,
		encoder:   newEncoder[G, P, E](encoder),
		encrypter: encrypter,
		committer: committer,
		rnd:       rnd,
	}
}

func (p Prover[G, P, E, C]) Commit(
	x sigma.Word[G, P],
	w sigma.Witness[G, P],
) (
	Commitment[C],
	Decommitment[G, P, E, C],
	error,
) {
	decomms := make([]sigma.Decommitment[C, P], p.k)
	encResps := make([]EncryptedResponse[G, P, E], p.k)
	rands := make([]probenc.RandomBytes, p.k)
	for i := uint(0); i < p.k; i++ {
		t, rt, err := p.sigmaP.Commit(x, w)
		if err != nil {
			return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("sigma protocol commit: %w", err)
		}
		ch0 := sigma.Challenge(false)
		s0 := p.sigmaP.Respond(x, w, rt, ch0)
		s0Bytes := p.encoder.EncodeResponse(s0)
		e0, r0, err := probenc.Encrypt(p.rnd, s0Bytes, p.encrypter)
		if err != nil {
			return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("encrypting response %d: %w", i, err)
		}
		decomms[i] = rt
		encResps[i] = EncryptedResponse[G, P, E]{t, e0}
		rands[i] = r0
	}

	data, err := p.encoder.EncodeEncryptedResponses(encResps)
	if err != nil {
		return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("encoding encrypted responses: %w", err)
	}
	respCom, respDecom, err := p.committer.Commit(data)
	if err != nil {
		return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("committing responses: %w", err)
	}
	com := respCom
	decom := Decommitment[G, P, E, C]{
		x,
		w,
		decomms,
		encResps,
		rands,
		respDecom,
	}
	return com, decom, nil
}

func (p Prover[G, P, E, C]) Respond(
	decom Decommitment[G, P, E, C],
	ch Challenge,
) Response[G, P, E, C] {
	// choices = [i in challenge]_{i in {0, ..., k-1}}.
	choices := make([]bool, p.k)
	for i := 0; i < len(ch); i++ {
		choices[ch[i]] = true
	}

	responses := make([]sigma.Response[G, P], p.k)
	for i := uint(0); i < p.k; i++ {
		ch := sigma.Challenge(choices[i])
		responses[i] = p.sigmaP.Respond(decom.x, decom.w, decom.decomms[i], ch)
	}

	rbs := make([]probenc.RandomBytes, p.k)
	for i := uint(0); i < p.k; i++ {
		if choices[i] {
			rbs[i] = decom.r[i]
		}
	}

	return Response[G, P, E, C]{
		encResps: decom.s,
		d:        decom.decom,
		s:        responses,
		r:        rbs,
	}
}
