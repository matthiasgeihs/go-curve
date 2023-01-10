package cd00

import (
	"fmt"

	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Decrypter[G curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	ver       sigma.Verifier[G, P]
	ext       sigma.Extractor[G, P]
	encoder   sigma.Encoder[G, P]
	decrypter probenc.Decrypter[E]
}

func NewDecrypter[
	G curve.Curve,
	P sigma.Protocol,
	E probenc.Scheme,
](
	ver sigma.Verifier[G, P],
	ext sigma.Extractor[G, P],
	encoder sigma.Encoder[G, P],
	decrypter probenc.Decrypter[E],
) *Decrypter[G, P, E] {
	return &Decrypter[G, P, E]{
		ver:       ver,
		ext:       ext,
		encoder:   encoder,
		decrypter: decrypter,
	}
}

func (d *Decrypter[C, P, E]) Decrypt(
	ct Ciphertext[C, P, E],
	x sigma.Word[C, P],
) (sigma.Witness[C, P], error) {
	u := len(ct.e)
	for i := 0; i < u; i++ {
		// Decrypt sigma response for challenge 0.
		e := ct.e[i]
		s0Bytes, err := d.decrypter.Decrypt(e)
		if err != nil {
			return nil, fmt.Errorf("decrypting: %w", err)
		}
		s0 := d.encoder.DecodeResponse(s0Bytes)
		s1 := ct.s[i]

		// Verify sigma response.
		t := ct.t[i]
		valid := d.ver.Verify(x, t, false, s0)
		if !valid {
			// Sigma response is invalid. Continue with next entry.
			continue
		}

		// Extract witness.
		tr0 := sigma.MakeTranscript(false, s0)
		tr1 := sigma.MakeTranscript(true, s1)
		w := d.ext.Extract(tr0, tr1)
		return w, nil
	}
	return nil, fmt.Errorf("decryption failure")
}
