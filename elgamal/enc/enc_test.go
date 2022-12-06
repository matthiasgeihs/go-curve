package enc_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	"github.com/matthiasgeihs/go-curve/elgamal/enc"
)

func TestCipher_secp256k1(t *testing.T) {
	instance := enc.NewCipher[secp256k1.Curve](
		secp256k1.NewGenerator(),
		rand.Reader,
	)
	testCipher(t, instance)
}

func TestCipher_edwards25519(t *testing.T) {
	instance := enc.NewCipher[edwards25519.Curve](
		edwards25519.NewGenerator(),
		rand.Reader,
	)
	testCipher(t, instance)
}

func testCipher[C curve.Curve](t *testing.T, instance enc.Cipher[C]) {
	sk, pk, err := instance.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Hi, Singapore!")
	ct, err := instance.Encrypt(pk, msg)
	if err != nil {
		t.Fatal(err)
	}

	msgDec := instance.Decrypt(sk, ct)
	if !bytes.Equal(msg, msgDec) {
		t.Error("Decrypted message not equal to encrypted message")
	}
}
