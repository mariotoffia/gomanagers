package ifctx

import "context"

// ConfigType specifies the type of `ServiceContext.Config` to fetch.
//
// Depending on the `ConfigType` the config may be casted to specific type.
type ConfigType string

const (
	// ConfigAWS is a `*aws.Config`
	ConfigAWS ConfigType = "aws"
)

// ServiceContext _is_ the service. A service setup
// a static context of which it creates sub-context on each request.
//
// This context derives from `context.Context`, hence, it may be used
// in all context based operations. For example, when _AWS Lambda_ the
// sub-context will embed the lambda context, hence the configured deadline
// is part of the `ServiceContext`.
//
// Therefore, if sub-context is created with a `context.Context`, all _Context_
// functions is reflecting the parameterized context.  This is true for the
// main, static, context as well that by default do have `context.Background()`
// if nothing else is specified.
type ServiceContext interface {
	context.Context

	// Config returns a configuration by specified `ConfigType`.
	//
	// This configuration is created / set at creation of `ServiceContext`
	// and will not change during it's lifetime. If you wish to alter / replace
	// it a sub-context needs to be created.
	//
	// If _ok_ is false, no config was stored by this type and `nil` is set in _config_.
	Config(t ConfigType) (config interface{}, ok bool)
}
