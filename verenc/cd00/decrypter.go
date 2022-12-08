package cd00

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

type Decrypter[C curve.Curve, P sigma.Protocol] struct {
	ext     sigma.Extractor[C, P]
	encoder sigma.Encoder[C, P]
}

func NewDecrypter[C curve.Curve, P sigma.Protocol](
	ext sigma.Extractor[C, P],
	encoder sigma.Encoder[C, P],
) Decrypter[C, P] {
	return Decrypter[C, P]{
		ext:     ext,
		encoder: encoder,
	}
}

func (d Decrypter[C, P]) Decrypt(
	ct Ciphertext[C, P],
	dec enc.Decrypt,
) (sigma.Witness[C, P], error) {
	c0, c1 := ct.c0, ct.c1
	s0, s1, err := func() (sigma.Response[C, P], sigma.Response[C, P], error) {
		decBytes, err := dec(ct.e)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting: %w", err)
		}
		sDec := d.encoder.DecodeResponse(decBytes)
		if ct.c {
			return sDec, ct.s, nil
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
