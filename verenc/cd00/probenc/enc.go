package probenc

type Encrypt func([]byte) (Ciphertext, Key, error)
type VerifyEncrypt func(Key, Ciphertext, []byte) bool
type Decrypt func(Ciphertext) ([]byte, error)
type Ciphertext interface{}
type Key interface{}
