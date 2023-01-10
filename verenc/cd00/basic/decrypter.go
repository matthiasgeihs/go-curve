package basic

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Decrypter[C curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	ver       sigma.Verifier[C, P]
	ext       sigma.Extractor[C, P]
	encoder   sigma.Encoder[C, P]
	decrypter probenc.Decrypter[E]
}

func NewDecrypter[C curve.Curve, P sigma.Protocol, E probenc.Scheme](
	ver sigma.Verifier[C, P],
	ext sigma.Extractor[C, P],
	encoder sigma.Encoder[C, P],
	decrypter probenc.Decrypter[E],
) Decrypter[C, P, E] {
	return Decrypter[C, P, E]{
		ver:       ver,
		ext:       ext,
		encoder:   encoder,
		decrypter: decrypter,
	}
}

func (d Decrypter[C, P, E]) Decrypt(
	ct Ciphertext[C, P, E],
	x sigma.Word[C, P],
) (sigma.Witness[C, P], error) {
	decBytes, err := d.decrypter.Decrypt(ct.e)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	sDec := d.encoder.DecodeResponse(decBytes)
	valid := d.ver.Verify(x, ct.t, !ct.c, sDec)
	if !valid {
		return nil, fmt.Errorf("invalid challenge reponse")
	}

	chi := chtoi(ct.c)
	s := [2]sigma.Response[C, P]{ct.s, sDec}
	t0 := sigma.MakeTranscript(false, s[chi])
	t1 := sigma.MakeTranscript(true, s[1-chi])
	w := d.ext.Extract(t0, t1)
	return w, nil
}
