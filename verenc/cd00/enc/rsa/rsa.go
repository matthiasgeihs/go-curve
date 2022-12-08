package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"log"

	"github.com/matthiasgeihs/go-curve/verenc/cd00/enc"
)

var newHasher = func() hash.Hash {
	return sha256.New()
}
var label []byte = nil

func NewInstace(rnd io.Reader, l int) (
	enc.Encrypt,
	enc.VerifyEncrypt,
	enc.Decrypt,
	error,
) {
	sk, err := rsa.GenerateKey(rnd, l)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating secret key: %w", err)
	}
	pk := sk.PublicKey

	encrypt := func(data []byte) (enc.Ciphertext, enc.Key, error) {
		var buf bytes.Buffer
		rndExt := io.TeeReader(rnd, &buf)
		ct, err := rsa.EncryptOAEP(newHasher(), rndExt, &pk, data, label)
		if err != nil {
			return nil, nil, err
		}
		return ct, buf.Bytes(), nil
	}

	verifyEncrypt := func(k enc.Key, ct enc.Ciphertext, data []byte) bool {
		buf := bytes.NewBuffer(k.([]byte))
		ctVer, err := rsa.EncryptOAEP(newHasher(), buf, &pk, data, label)
		if err != nil {
			log.Printf("Warning: encrypt failed: %v", err)
			return false
		}
		return bytes.Equal(ct.([]byte), ctVer)
	}

	decrypt := func(ct enc.Ciphertext) ([]byte, error) {
		return rsa.DecryptOAEP(newHasher(), rnd, sk, ct.([]byte), label)
	}

	return encrypt, verifyEncrypt, decrypt, nil
}
