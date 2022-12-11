package binary

import (
	"github.com/matthiasgeihs/go-curve/curve"
	"github.com/matthiasgeihs/go-curve/sigma"
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
	ch1 := chToScalar(ext.gen, t1.Challenge.(Challenge))
	ch2 := chToScalar(ext.gen, t2.Challenge.(Challenge))
	t1Dlog := sigma.MakeTranscript[C, dlog.Protocol](ch1, t1.Response)
	t2Dlog := sigma.MakeTranscript[C, dlog.Protocol](ch2, t2.Response)
	return ext.base.Extract(t1Dlog, t2Dlog)
}
