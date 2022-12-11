package binary

import (
	"github.com/matthiasgeihs/go-curve/curve"
	sigmabase "github.com/matthiasgeihs/go-curve/sigma"
	sigma "github.com/matthiasgeihs/go-curve/sigma/binary"
	"github.com/matthiasgeihs/go-curve/sigma/dlog"
)

type Extractor[C curve.Curve] struct {
	base dlog.Extractor[C]
	gen  curve.Generator[C]
}

func NewExtractor[C curve.Curve](
	gen curve.Generator[C],
) Extractor[C] {
	return Extractor[C]{
		base: dlog.NewExtractor(gen),
		gen:  gen,
	}
}

func (ext Extractor[C]) Extract(t1, t2 sigma.Transcript[C, Protocol]) sigma.Witness[C, Protocol] {
	ch1 := chToScalar(ext.gen, t1.Challenge)
	ch2 := chToScalar(ext.gen, t2.Challenge)
	t1Dlog := sigmabase.MakeTranscript[C, dlog.Protocol](ch1, t1.Response)
	t2Dlog := sigmabase.MakeTranscript[C, dlog.Protocol](ch2, t2.Response)
	return ext.base.Extract(t1Dlog, t2Dlog)
}
