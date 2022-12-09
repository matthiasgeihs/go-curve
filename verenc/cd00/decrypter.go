package cd00

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Decrypter[C curve.Curve, P sigma.Protocol] struct {
	ver     sigma.Verifier[C, P]
	ext     sigma.Extractor[C, P]
	encoder sigma.Encoder[C, P]
}

func NewDecrypter[C curve.Curve, P sigma.Protocol](
	ver sigma.Verifier[C, P],
	ext sigma.Extractor[C, P],
	encoder sigma.Encoder[C, P],
) Decrypter[C, P] {
	return Decrypter[C, P]{
		ver:     ver,
		ext:     ext,
		encoder: encoder,
	}
}

func (d Decrypter[C, P]) Decrypt(
	ct Ciphertext[C, P],
	x sigma.Word[C, P],
	dec probenc.Decrypt,
) (sigma.Witness[C, P], error) {
	decBytes, err := dec(ct.e)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	ch := ct.sigmaCh
	chi := chtoi(ct.c)
	sDec := d.encoder.DecodeResponse(decBytes)
	valid := d.ver.Verify(x, ct.t, ch[1-chi], sDec)
	if !valid {
		return nil, fmt.Errorf("invalid challenge reponse")
	}

	s := [2]sigma.Response[C, P]{ct.s, sDec}
	t0 := sigma.MakeTranscript(ch[0], s[chi])
	t1 := sigma.MakeTranscript(ch[1], s[1-chi])
	w := d.ext.Extract(t0, t1)
	return w, nil
}
