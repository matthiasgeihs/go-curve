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
	t      sigma.Commitment[C, P]
	c      Challenge
	c0, c1 sigma.Challenge[C, P]
	e      probenc.Ciphertext
	s      sigma.Response[C, P]
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
	sigmaCh := func() sigma.Challenge[C, P] {
		if ch {
			return com.ch1
		}
		return com.ch0
	}()

	b := v.sigmaV.Verify(x, com.t, sigmaCh, resp.s)
	if !b {
		return Ciphertext[C, P]{}, fmt.Errorf("invalid sigma proof")
	}

	eCh, eCt := func() (probenc.Ciphertext, probenc.Ciphertext) {
		if ch {
			return com.e1, com.e0
		}
		return com.e0, com.e1
	}()

	sBytes := v.encoder.EncodeResponse(resp.s)
	valid := verEnc(resp.r, eCh, sBytes)
	if !valid {
		return Ciphertext[C, P]{}, fmt.Errorf("invalid encryption")
	}
	return Ciphertext[C, P]{com.t, ch, com.ch0, com.ch1, eCt, resp.s}, nil
}
