package enc

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
)

type Encrypt[C curve.Curve, P sigma.Protocol[C]] func([]byte) (Ciphertext, Key)
type Ciphertext interface{}
type Key interface{}
