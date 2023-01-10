package probenc

import (
	"bytes"
	"fmt"
	"io"
)

type Scheme interface{}

type Encrypter[S Scheme] interface {
	Encrypt(io.Reader, []byte) (Ciphertext[S], error)
}
type Decrypter[S Scheme] interface {
	Decrypt(Ciphertext[S]) ([]byte, error)
}
type Ciphertext[S Scheme] []byte

type RandomBytes []byte

// Encrypt encrypts `data` using the probabilistic encryption algorithm `enc`
// and using `rnd` as source of randomness. It returns the ciphertext and the
// bytes consumed by `rnd`.
func Encrypt[E Scheme](
	rnd io.Reader,
	data []byte,
	enc Encrypter[E],
) (Ciphertext[E], RandomBytes, error) {
	var buf bytes.Buffer
	rndExt := io.TeeReader(rnd, &buf)
	ct, err := enc.Encrypt(rndExt, data)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypting data: %w", err)
	}
	r := buf.Bytes()
	return ct, r, nil
}
