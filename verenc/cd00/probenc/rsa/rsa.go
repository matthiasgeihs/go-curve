package rsa

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"github.com/matthiasgeihs/go-curve/verenc/cd00/probenc"
)

type Scheme struct{}

var newHasher = func() hash.Hash {
	return sha256.New()
}
var label []byte = nil

func NewInstace(rnd io.Reader, l int) (
	probenc.Encrypter[Scheme],
	probenc.Decrypter[Scheme],
	error,
) {
	sk, err := rsa.GenerateKey(rnd, l)
	if err != nil {
		return Encrypter{}, Decrypter{}, fmt.Errorf("generating secret key: %w", err)
	}
	pk := sk.PublicKey

	encrypter := Encrypter{
		pk: &pk,
	}
	decrypter := Decrypter{
		sk:  sk,
		rnd: rnd,
	}
	return encrypter, decrypter, nil
}

type Encrypter struct {
	pk *rsa.PublicKey
}

func (e Encrypter) Encrypt(rnd io.Reader, data []byte) (probenc.Ciphertext[Scheme], error) {
	ct, err := rsa.EncryptOAEP(newHasher(), rnd, e.pk, data, label)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

type Decrypter struct {
	sk  *rsa.PrivateKey
	rnd io.Reader
}

func (d Decrypter) Decrypt(ct probenc.Ciphertext[Scheme]) ([]byte, error) {
	return rsa.DecryptOAEP(newHasher(), d.rnd, d.sk, ct, label)
}
