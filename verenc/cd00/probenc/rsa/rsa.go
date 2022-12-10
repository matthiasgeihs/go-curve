package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

var newHasher = func() hash.Hash {
	return sha256.New()
}
var label []byte = nil

func NewInstace(rnd io.Reader, l int) (
	probenc.Encrypt,
	probenc.Decrypt,
	error,
) {
	sk, err := rsa.GenerateKey(rnd, l)
	if err != nil {
		return nil, nil, fmt.Errorf("generating secret key: %w", err)
	}
	pk := sk.PublicKey

	encrypt := func(rnd io.Reader, data []byte) (probenc.Ciphertext, error) {
		var buf bytes.Buffer
		rndExt := io.TeeReader(rnd, &buf)
		ct, err := rsa.EncryptOAEP(newHasher(), rndExt, &pk, data, label)
		if err != nil {
			return nil, err
		}
		return ct, nil
	}

	decrypt := func(ct probenc.Ciphertext) ([]byte, error) {
		return rsa.DecryptOAEP(newHasher(), rnd, sk, ct, label)
	}

	return encrypt, decrypt, nil
}
