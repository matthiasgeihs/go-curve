package cd00

import (
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Verifier[C curve.Curve, P sigma.Protocol] struct {
	rnd     io.Reader
	sigmaV  sigma.Verifier[C, P]
	encoder sigma.Encoder[C, P]
}
type Word[C curve.Curve] curve.Point[C]
type Challenge bool
type Ciphertext[C curve.Curve, P sigma.Protocol] struct {
	t       sigma.Commitment[C, P]
	c       Challenge
	sigmaCh [2]sigma.Challenge[C, P]
	e       probenc.Ciphertext
	s       sigma.Response[C, P]
}

func NewVerifier[C curve.Curve, P sigma.Protocol](
	rnd io.Reader,
	sigmaV sigma.Verifier[C, P],
	encoder sigma.Encoder[C, P],
) Verifier[C, P] {
	return Verifier[C, P]{
		rnd:     rnd,
		sigmaV:  sigmaV,
		encoder: encoder,
	}
}

func (v Verifier[C, P]) Challenge(Commitment[C, P]) Challenge {
	c := func() bool {
		var b [1]byte
		v.rnd.Read(b[:])
		return b[0]&1 == 1
	}()
	return Challenge(c)
}

func (v Verifier[C, P]) Verify(
	x sigma.Word[C, P],
	com Commitment[C, P],
	ch Challenge,
	resp Response[C, P],
	verEnc probenc.VerifyEncrypt,
) (Ciphertext[C, P], error) {
	chi := chtoi(ch)
	sigmaCh := com.ch[chi]

	b := v.sigmaV.Verify(x, com.t, sigmaCh, resp.s)
	if !b {
		return Ciphertext[C, P]{}, fmt.Errorf("invalid sigma proof")
	}

	eCh, eCt := com.e[chi], com.e[1-chi]
	sBytes := v.encoder.EncodeResponse(resp.s)
	valid := verEnc(resp.r, eCh, sBytes)
	if !valid {
		return Ciphertext[C, P]{}, fmt.Errorf("invalid encryption")
	}
	return Ciphertext[C, P]{
		com.t,
		ch,
		com.ch,
		eCt,
		resp.s,
	}, nil
}
