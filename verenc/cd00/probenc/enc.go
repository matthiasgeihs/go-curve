package probenc

import "io"

type Encrypt func(io.Reader, []byte) (Ciphertext, error)
type Decrypt func(Ciphertext) ([]byte, error)
type Ciphertext []byte
