package awskms

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mariotoffia/goservice/interfaces/ifcrypto"
	"github.com/mariotoffia/goservice/interfaces/ifctx"
	"github.com/mariotoffia/goservice/model/coremodel"
	"github.com/mariotoffia/goservice/utils"
)

// AwsKms implements xyz interfaces to use the
// _AWS Key Management System_ as backing sign and crypto.
type AwsKms struct {
}

// Sign implements the `ifkms.Signer` interface
func (km *AwsKms) Sign(
	c ifctx.ServiceContext,
	msg []byte,
	key ifcrypto.Key,
	signAlgorithm ifcrypto.SignAlgorithm,
	tags ...coremodel.Meta,
) error {

	client, err := kmsClientFromContext(c)
	if err != nil {
		return err
	}

	client.Sign(c, &kms.SignInput{
		KeyId: utils.ToStringPtrNil(key.GetID()),
	})

	return nil
}

// kmsClientFromContext creates a new `*kms.Client` from context.
func kmsClientFromContext(
	c ifctx.ServiceContext,
	optFns ...func(*kms.Options),
) (*kms.Client, error) {

	if cfg, ok := c.Config(ifctx.ConfigAWS); ok {

		config := cfg.(*aws.Config)

		return kms.NewFromConfig(*config, optFns...), nil

	}

	return nil, fmt.Errorf("no AWS configuration is present")

}
