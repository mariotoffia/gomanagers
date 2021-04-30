package ctx

import (
	"context"
	"time"

	"github.com/mariotoffia/goservice/interfaces/ifctx"
)

// ServiceContextImpl is a implementation of `ifctx.ServiceContext`.
type ServiceContextImpl struct {
	// backing is the `context.Context` exposed - hence it is replaceable
	backing context.Context
	// config contains all the configuration available for this context instance.
	config map[ifctx.ConfigType]interface{}
}

func (c *ServiceContextImpl) Config(t ifctx.ConfigType) (config interface{}, ok bool) {
	config, ok = c.config[t]
	return
}

func (c *ServiceContextImpl) Deadline() (deadline time.Time, ok bool) {
	return c.backing.Deadline()
}

func (c *ServiceContextImpl) Done() <-chan struct{} {
	return c.backing.Done()
}

func (c *ServiceContextImpl) Err() error {
	return c.backing.Err()
}

func (c *ServiceContextImpl) Value(key interface{}) interface{} {
	return c.backing.Value(key)
}
