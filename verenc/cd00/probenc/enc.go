package probenc

import "io"

type Scheme interface{}

type Encrypter[S Scheme] interface {
	Encrypt(io.Reader, []byte) (Ciphertext[S], error)
}
type Decrypter[S Scheme] interface {
	Decrypt(Ciphertext[S]) ([]byte, error)
}
type Ciphertext[S Scheme] []byte
