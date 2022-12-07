package enc

type Encrypt func([]byte) (Ciphertext, Key)
type Decrypt func(Ciphertext) []byte
type Ciphertext interface{}
type Key interface{}
