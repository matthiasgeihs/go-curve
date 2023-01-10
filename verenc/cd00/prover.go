package cd00

import (
	"bytes"
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
	encoder   sigma.Encoder[G, P]
	encrypter probenc.Encrypter[E]
	committer commit.Committer[C]
	rnd       io.Reader
	k         uint
}
type Commitment[C commit.Scheme] commit.Commitment[C]
type Decommitment[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	s     []EncryptedResponse[G, P, E]
	r     []RandomBytes
	decom commit.Decommitment[C]
}
type Challenge []uint
type Response[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	d commit.Decommitment[C]
	s []sigma.Response[G, P]
}

type EncryptedResponse[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	t sigma.Commitment[C, P]
	r probenc.Ciphertext[E]
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
		encoder:   encoder,
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
	resps := make([]EncryptedResponse[G, P, E], p.k)
	rands := make([]RandomBytes, p.k)
	for i := uint(0); i < p.k; i++ {
		t, rt, err := p.sigmaP.Commit(x, w)
		if err != nil {
			return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("sigma protocol commit: %w", err)
		}
		ch0 := sigma.Challenge(false)
		s0 := p.sigmaP.Respond(x, w, rt, ch0)
		s0Bytes := p.encoder.EncodeResponse(s0)
		e0, r0, err := encrypt(p.rnd, s0Bytes, p.encrypter)
		if err != nil {
			return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("encrypting response %i: %w", i, err)
		}
		resps[i] = EncryptedResponse[G, P, E]{t, e0}
		rands[i] = r0
	}

	data := p.encoder.EncodeEncryptedResponses(resps)
	respCom, respDecom, err := p.committer.Commit(data)
	if err != nil {
		return nil, Decommitment[G, P, E, C]{}, fmt.Errorf("committing responses: %w", err)
	}
	com := respCom
	decom := Decommitment[G, P, E, C]{
		resps,
		rands,
		respDecom,
	}
	return com, decom, nil
}

type RandomBytes []byte

// encrypt encrypts `data` using the probabilistic encryption algorithm `enc`
// using `rnd` as source of randomness. It returns the ciphertext and the bytes
// consumed from `rnd`.
func encrypt[E probenc.Scheme](
	rnd io.Reader,
	data []byte,
	enc probenc.Encrypter[E],
) (probenc.Ciphertext[E], RandomBytes, error) {
	var buf bytes.Buffer
	rndExt := io.TeeReader(rnd, &buf)
	ct, err := enc.Encrypt(rndExt, data)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting data: %w", err)
	}
	r := buf.Bytes()
	return ct, r, nil
}

func (p Prover[G, P, E, C]) Respond(
	decom Decommitment[G, P, E, C],
	ch Challenge,
) Response[G, P, E] {

	return Response[G, P, E]{}
}

func chtoi(ch sigma.Challenge) int {
	if ch {
		return 1
	}
	return 0
}
