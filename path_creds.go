package hcpsecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/models"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *hcpBackend) pathCreds() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
			OperationVerb:   "generate",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "credentials",
				},
			},
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

func (b *hcpBackend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	role := new(hcpRole)
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error reading role configuration")
	}

	cl, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	sp, err := createServicePrincipal(ctx, req, cl, role.Name)
	if err != nil {
		return nil, err
	}

	// create service principal key
	spk, err := createServicePrincipalKey(cl, sp)
	if err != nil {
		return nil, err
	}

	resp := b.Secret("hcp-service-principal-key").Response(
		// data
		map[string]interface{}{
			"client_id":     spk.Key.ClientID,
			"client_secret": spk.ClientSecret,
		},
		// internal data
		map[string]interface{}{
			"vault_role":        name,
			"resource_name":     spk.Key.ResourceName,
			"service_principal": sp.ResourceName,
			"created_at":        spk.Key.CreatedAt,
		},
	)

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *hcpBackend) renewCredentials(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vaultRole, ok := req.Secret.InternalData["vault_role"]
	if !ok {
		return nil, errors.New("internal data 'vault_role' not found")
	}

	entry, err := req.Storage.Get(ctx, "roles/"+vaultRole.(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	role := new(hcpRole)
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error reading role configuration")
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *hcpBackend) revokeCredentials(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	spkResourceName, ok := req.Secret.InternalData["resource_name"]
	if !ok {
		return nil, errors.New("internal data 'resource_name' not found")
	}

	spResourceName, ok := req.Secret.InternalData["service_principal"]
	if !ok {
		return nil, errors.New("internal data 'service_principal' not found")
	}

	cl, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	spk := &models.HashicorpCloudIamServicePrincipalKey{ResourceName: spkResourceName.(string)}
	if err := deleteServicePrincipalKey(cl, spk); err != nil {
		return nil, err
	}

	sp := &models.HashicorpCloudIamServicePrincipal{ResourceName: spResourceName.(string)}
	if err := deleteServicePrincipal(cl, sp); err != nil {
		return nil, err
	}

	return nil, nil
}

const pathCredsHelpSyn = `
Generate a dynamic, short-lived HashiCorp Cloud Platform (HCP) Service 
Principal and Service Principal Key.
`

const pathCredsHelpDesc = `
This path will create a unique HashiCorp Cloud Platform (HCP) Service 
Principal within the configured HCP Project. It will then create a 
Service Principal Key under the Service Principal.

The HCP credentials are time-based and are automatically revoked 
when the Vault lease expires. During the revocation process, the 
service principal key will be deleted first, then the service principal 
will be deleted.

Service Principals can only have two Service Principal Keys.
Projects can only have five Service Principals.
`
