package awskms

import (
	"testing"

	"github.com/ahmetb/go-linq/v3"
	"github.com/stretchr/testify/assert"
)

func TestToUseLinq(t *testing.T) {

	arr := []int{1, 2, 3, 4}

	linq.From(arr)
	assert.Equal(t, 4, len(arr))
}
