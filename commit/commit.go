package commit

type Scheme interface{}

type Committer[C Scheme] interface {
	Commit([]byte) (Commitment[C], Decommitment[C], error)
}

type Verifier[C Scheme] interface {
	Verify(Commitment[C], Decommitment[C], []byte) error
}

type Commitment[C Scheme] interface{}
type Decommitment[C Scheme] interface{}
