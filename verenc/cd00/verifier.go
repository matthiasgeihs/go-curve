package cd00

import (
	"bytes"
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Verifier[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	rnd       io.Reader
	sigmaV    sigma.Verifier[C, P]
	encoder   sigma.Encoder[C, P]
	encrypter probenc.Encrypter[E]
}
type Word[C curve.Curve] curve.Point[C]
type Challenge bool
type Ciphertext[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	t       sigma.Commitment[C, P]
	c       Challenge
	sigmaCh [2]sigma.Challenge
	e       probenc.Ciphertext[E]
	s       sigma.Response[C, P]
}

func NewVerifier[C curve.Curve, P sigma.Protocol, E probenc.Scheme](
	rnd io.Reader,
	sigmaV sigma.Verifier[C, P],
	encoder sigma.Encoder[C, P],
	encrypter probenc.Encrypter[E],
) Verifier[C, P, E] {
	return Verifier[C, P, E]{
		rnd:       rnd,
		sigmaV:    sigmaV,
		encoder:   encoder,
		encrypter: encrypter,
	}
}

func (v Verifier[C, P, E]) Challenge(Commitment[C, P, E]) Challenge {
	c := func() bool {
		var b [1]byte
		v.rnd.Read(b[:])
		return b[0]&1 == 1
	}()
	return Challenge(c)
}

func (v Verifier[C, P, E]) Verify(
	x sigma.Word[C, P],
	com Commitment[C, P, E],
	ch Challenge,
	resp Response[C, P, E],
) (Ciphertext[C, P, E], error) {
	chi := chtoi(ch)
	sigmaCh := com.ch[chi]

	b := v.sigmaV.Verify(x, com.t, sigmaCh, resp.s)
	if !b {
		return Ciphertext[C, P, E]{}, fmt.Errorf("invalid sigma proof")
	}

	eCh, eCt := com.e[chi], com.e[1-chi]
	sBytes := v.encoder.EncodeResponse(resp.s)
	buf := bytes.NewBuffer(resp.r)
	ctEnc, err := v.encrypter.Encrypt(buf, sBytes)
	if err != nil {
		return Ciphertext[C, P, E]{}, fmt.Errorf("failed to encrypt")
	} else if !bytes.Equal(eCh, ctEnc) {
		return Ciphertext[C, P, E]{}, fmt.Errorf("invalid encryption")
	}
	return Ciphertext[C, P, E]{
		com.t,
		ch,
		com.ch,
		eCt,
		resp.s,
	}, nil
}
