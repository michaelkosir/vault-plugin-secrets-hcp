package hcpsecrets

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *hcpBackend) pathConfigRotate() *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "rotate",
				},
			},
		},
		HelpSynopsis:    pathConfigRotateHelpSyn,
		HelpDescription: pathConfigRotateHelpDesc,
	}
}

func (b *hcpBackend) pathConfigRotateWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cl, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	sp, spk, err := getCallerIdentity(ctx, req, cl)
	if err != nil {
		return nil, err
	}

	newSPK, err := createServicePrincipalKey(cl, sp)
	if err != nil {
		return nil, err
	}

	if err := replaceConfigServicePrincipalKey(ctx, req, newSPK); err != nil {
		return nil, err
	}

	// reset client, to load new credentials
	b.client = nil

	if err := deleteServicePrincipalKey(cl, spk); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathConfigRotateHelpSyn = `
Rotate the service principal key used for communicating with the HashiCorp Cloud Platform (HCP).
`

const pathConfigRotateHelpDesc = `
This path will keep the intial service principal, but rotate the service principal key used to
communicate with the HashiCorp Cloud Platform (HCP).
`
