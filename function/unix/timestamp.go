package unix

import (
	"github.com/project-flogo/core/data"
	"github.com/project-flogo/core/support/log"
	"time"

	"github.com/project-flogo/core/data/expression/function"
)

type Timestamp struct {
}

func init() {
	function.Register(&Timestamp{})
}

func (s *Timestamp) Name() string {
	return "timestamp"
}

func (s *Timestamp) GetCategory() string {
	return "datetime"
}

func (s *Timestamp) Sig() (paramTypes []data.Type, isVariadic bool) {
	return []data.Type{}, false
}

func (s *Timestamp) Eval(params ...interface{}) (interface{}, error) {
	log.RootLogger().Debugf("Returns the current unix timestamp")
	return time.Now().Unix(), nil
}
