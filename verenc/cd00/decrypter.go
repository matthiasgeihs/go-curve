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
	c0, c1 := ct.c0, ct.c1
	s0, s1, err := func() (sigma.Response[C, P], sigma.Response[C, P], error) {
		decBytes, err := dec(ct.e)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting: %w", err)
		}
		sDec := d.encoder.DecodeResponse(decBytes)
		if ct.c {
			valid := d.ver.Verify(x, ct.t, c0, sDec)
			if !valid {
				return nil, nil, fmt.Errorf("invalid challenge reponse 1")
			}
			return sDec, ct.s, nil
		}
		valid := d.ver.Verify(x, ct.t, c1, sDec)
		if !valid {
			return nil, nil, fmt.Errorf("invalid challenge reponse 0")
		}
		return ct.s, sDec, nil
	}()
	if err != nil {
		return nil, err
	}

	t0 := sigma.MakeTranscript(c0, s0)
	t1 := sigma.MakeTranscript(c1, s1)
	w := d.ext.Extract(t0, t1)
	return w, nil
}
