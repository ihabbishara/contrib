package unix

import (
	"fmt"
	"github.com/project-flogo/core/data/expression/function"
	"github.com/stretchr/testify/assert"
	"testing"
)

func init() {
	function.ResolveAliases()
}

func TestTimestamp_Eval(t *testing.T) {
	n := Timestamp{}
	tmstmp, _ := n.Eval(nil)
	assert.NotNil(t, tmstmp)
	fmt.Println(tmstmp)
}
