package cd00

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

type Decrypter[C curve.Curve, P sigma.Protocol[C]] struct {
	ext     sigma.Extractor[C, P]
	encoder sigma.Encoder[C, P]
}

func (d Decrypter[C, P]) Decrypt(
	ct Ciphertext[C, P],
	dec enc.Decrypt,
) (sigma.Witness[C, P], error) {
	c0, c1 := ct.c0, ct.c1
	s0, s1 := func() (sigma.Response[C, P], sigma.Response[C, P]) {
		decBytes := dec(ct.e)
		sDec := d.encoder.DecodeResponse(decBytes)
		if ct.c {
			return sDec, ct.s
		}
		return ct.s, sDec
	}()

	t0 := sigma.MakeTranscript(c0, s0)
	t1 := sigma.MakeTranscript(c1, s1)
	w := d.ext.Extract(t0, t1)
	return w, nil
}
