package cd00

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/matthiasgeihs/go-curve/commit"
	"github.com/matthiasgeihs/go-curve/curve"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Verifier[G curve.Curve, P sigma.Protocol, E probenc.Scheme, C commit.Scheme] struct {
	rnd       io.Reader
	k         uint
	u         uint
	encoder   *encoder[G, P, E]
	comV      commit.Verifier[C]
	sigmaV    sigma.Verifier[G, P]
	encrypter probenc.Encrypter[E]
}

type Ciphertext[G curve.Curve, P sigma.Protocol, E probenc.Scheme] struct {
	t []sigma.Commitment[G, P]
	s []sigma.Response[G, P]
	e []probenc.Ciphertext[E]
}

func NewVerifier[
	G curve.Curve,
	P sigma.Protocol,
	E probenc.Scheme,
	C commit.Scheme,
](
	rnd io.Reader,
	k uint,
	u uint,
	comV commit.Verifier[C],
	sigmaV sigma.Verifier[G, P],
	sigmaEnc sigma.Encoder[G, P],
	encrypter probenc.Encrypter[E],
) *Verifier[G, P, E, C] {
	return &Verifier[G, P, E, C]{
		rnd:       rnd,
		k:         k,
		u:         u,
		encoder:   newEncoder[G, P, E](sigmaEnc),
		comV:      comV,
		sigmaV:    sigmaV,
		encrypter: encrypter,
	}
}

func (v *Verifier[G, P, E, C]) Challenge(Commitment[C]) (Challenge, error) {
	return nChooseK(v.k, v.u, v.rnd)
}

// nChooseK returns k random elements from {0, ..., n-1}.
func nChooseK(n, k uint, rnd io.Reader) ([]uint, error) {
	if k > n {
		return nil, fmt.Errorf("k > n")
	}

	// Fill bag with 0, ..., n-1.
	bag := make([]uint, n)
	for i := uint(0); i < n; i++ {
		bag[i] = i
	}

	// Select k numbers from bag at random.
	selection := make([]uint, k)
	l := int64(len(bag))
	for i := uint(0); i < k; i++ {
		jBig, err := rand.Int(rnd, big.NewInt(l))
		if err != nil {
			return nil, fmt.Errorf("sampling random number: %w", err)
		}
		j := jBig.Int64()
		selection[i] = bag[j]

		// Swap out chosen element.
		bag[l-1], bag[j] = bag[j], bag[l-1]

		//Reduce selection range.
		l -= 1
	}
	return selection, nil
}

func (v *Verifier[G, P, E, C]) Verify(
	x sigma.Word[G, P],
	com Commitment[G],
	ch Challenge,
	resp Response[G, P, E, C],
) (Ciphertext[G, P, E], error) {
	// Open commitment.
	encRespsBytes, err := v.encoder.EncodeEncryptedResponses(resp.encResps)
	if err != nil {
		return Ciphertext[G, P, E]{}, fmt.Errorf("encoding encrypted responses: %w", err)
	}
	err = v.comV.Verify(com, resp.d, encRespsBytes)
	if err != nil {
		return Ciphertext[G, P, E]{}, fmt.Errorf("verifying commitment: %w", err)
	}

	// Verify sigma responses.

	// choices = [i in challenge]_{i in {0, ..., k-1}}.
	choices := make([]bool, v.k)
	for i := 0; i < len(ch); i++ {
		choices[ch[i]] = true
	}

	comms := make([]sigma.Commitment[G, P], v.u)
	resps := make([]sigma.Response[G, P], v.u)
	encs := make([]probenc.Ciphertext[E], v.u)
	storeI := 0
	for i := uint(0); i < v.k; i++ {
		if choices[i] {
			// Verify sigma response for challenge 1.
			comm := resp.encResps[i].t
			sigmaResp := resp.s[i]
			b := v.sigmaV.Verify(x, comm, true, sigmaResp)
			if !b {
				return Ciphertext[G, P, E]{}, fmt.Errorf("invalid sigma proof")
			}

			// Append to ciphertext.
			comms[storeI] = comm
			resps[storeI] = sigmaResp
			encs[storeI] = resp.encResps[i].e
			storeI += 1
		} else {
			// Verify sigma response for challenge 0.
			b := v.sigmaV.Verify(x, resp.encResps[i].t, false, resp.s[i])
			if !b {
				return Ciphertext[G, P, E]{}, fmt.Errorf("invalid sigma proof")
			}

			// Check correct encryption.
			sBytes := v.encoder.EncodeResponse(resp.s[i])
			rBuf := bytes.NewBuffer(resp.r[i])
			ctVer, err := v.encrypter.Encrypt(rBuf, sBytes)
			ctCom := resp.encResps[i].e
			if err != nil {
				return Ciphertext[G, P, E]{}, fmt.Errorf("failed to encrypt: %w", err)
			} else if !bytes.Equal(ctCom, ctVer) {
				return Ciphertext[G, P, E]{}, fmt.Errorf("invalid encryption")
			}
		}
	}

	return Ciphertext[G, P, E]{
		t: comms,
		s: resps,
		e: encs,
	}, nil
}
