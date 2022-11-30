package ecdsa_test

import (
	"crypto/rand"
	"testing"

	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/curve/edwards25519"
	"github.com/matthiasgeihs/go-curve/curve/secp256k1"
	"github.com/matthiasgeihs/go-curve/ecdsa"
)

func TestECDSA_secp256k1(t *testing.T) {
	instance := ecdsa.NewECDSA[secp256k1.Curve](
		secp256k1.NewGenerator(),
		rand.Reader,
	)
	testECDSA(t, instance)
}

func TestECDSA_edwards25519(t *testing.T) {
	instance := ecdsa.NewECDSA[edwards25519.Curve](
		edwards25519.NewGenerator(),
		rand.Reader,
	)
	testECDSA(t, instance)
}

func testECDSA[C curve.Curve](t *testing.T, instance ecdsa.ECDSA[C]) {
	sk, pk, err := instance.KeyGen()
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("Hello, Singapore!")
	sig, err := instance.Sign(sk, msg)
	if err != nil {
		t.Fatal(err)
	}

	valid := instance.Verify(pk, msg, sig)
	if !valid {
		t.Error("Signature invalid")
	}
}
