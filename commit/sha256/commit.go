package sha256

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/matthiasgeihs/go-curve/commit"
)

type Scheme struct{}

type Committer struct {
	rnd io.Reader
}

func NewCommitter(rnd io.Reader) *Committer {
	return &Committer{
		rnd: rnd,
	}
}

func (c *Committer) Commit(data []byte) (commit.Commitment[Scheme], commit.Decommitment[Scheme], error) {
	var nonce [32]byte
	_, err := c.rnd.Read(nonce[:])
	if err != nil {
		return nil, nil, fmt.Errorf("reading rng: %w", err)
	}

	hasher := sha256.New()
	_, err = hasher.Write(nonce[:])
	if err != nil {
		return nil, nil, fmt.Errorf("writing nonce: %w", err)
	}
	h := hasher.Sum(data)
	return h, nonce, nil
}
