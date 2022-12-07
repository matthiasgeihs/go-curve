package cd00

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Decrypter[C curve.Curve, P sigma.Protocol[C]] struct {
	ext sigma.Extractor[C, P]
}

type Decrypt func()

func (d Decrypter[C, P]) Decrypt(
	ct Ciphertext[C, P],
	dec Decrypt,
) ([]byte, error) {
	c0 := ct.c
	s0 := ct.s
	c1, s1 := dec(ct.e)

	t0 := sigma.MakeTranscript[C, P](c0, s0)
	t1 := sigma.MakeTranscript[C, P](c1, s1)
	w := d.ext.Extract(t0, t1)
	return w, nil
}
