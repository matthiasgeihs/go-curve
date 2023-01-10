package sha256

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/matthiasgeihs/go-curve/commit"
)

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (Verifier) Verify(com commit.Commitment[Scheme], decom commit.Decommitment[Scheme], data []byte) error {
	nonce := decom.([32]byte)
	hCom := com.([]byte)

	hasher := sha256.New()
	_, err := hasher.Write(nonce[:])
	if err != nil {
		return fmt.Errorf("writing nonce: %w", err)
	}
	hVer := hasher.Sum(data)
	if !bytes.Equal(hCom, hVer) {
		return fmt.Errorf("invalid decommitment")
	}
	return nil
}
