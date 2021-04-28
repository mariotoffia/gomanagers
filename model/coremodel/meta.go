package coremodel

// MetaTypes represents well-known tag types.
type MetaTypes string

const (
	// TagGrantToken represent the same mechanism as described
	// https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#grant_token#Here.
	MetaGrantToken MetaTypes = "grant-token"
)

type Meta struct {
	Name  MetaTypes
	Value interface{}
}

type Tag struct {
	Name  string
	Value interface{}
}
