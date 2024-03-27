package hcpsecrets

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const operationPrefix = "hcp"

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type hcpBackend struct {
	*framework.Backend
	client *hcpClient
}

func Backend(c *logical.BackendConfig) *hcpBackend {
	var b hcpBackend

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(helpMessage),
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"config", // seal wrapped with extra encryption, if possible
			},
		},
		Paths: framework.PathAppend(
			b.pathRoles(),
			[]*framework.Path{
				b.pathConfig(),
				b.pathConfigRotate(),
				b.pathCreds(),
			},
		),
		Secrets: []*framework.Secret{
			b.hcpServicePrincipalKey(),
		},
	}

	return &b
}

func (b *hcpBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.client = nil
	}
}

func (b *hcpBackend) hcpServicePrincipalKey() *framework.Secret {
	return &framework.Secret{
		Type: "hcp-service-principal-key",
		Fields: map[string]*framework.FieldSchema{
			"client_id": {
				Type:        framework.TypeString,
				Description: "Service principal client ID used to authenticate to HCP",
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "Service principal client secret used to authenticate to HCP",
			},
		},
		Revoke: b.revokeCredentials,
		Renew:  b.renewCredentials,
	}
}

const helpMessage = `
The hcp secrets backend dynamically generates organization
and project level service principal keys for the HashiCorp Cloud Platform (HCP).
`
