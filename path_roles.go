package hcpsecrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type hcpRole struct {
	Name   string        `json:"name"`
	Role   string        `json:"role"`
	TTL    time.Duration `json:"ttl,omitempty"`
	MaxTTL time.Duration `json:"max_ttl,omitempty"`
}

func (b *hcpBackend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefix,
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"role": {
					Type:        framework.TypeString,
					Description: "Role of the service principal created in the HashiCorp Cloud Platform (HCP). Valid values: `Admin`, `Contributor`, `Viewer`",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use mount/system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use mount/system default.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "role",
					},
				},
			},
			HelpSynopsis:    pathRolesHelpSyn,
			HelpDescription: pathRolesHelpDesc,
		},
		{
			Pattern: "roles/?",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: operationPrefix,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
					DisplayAttrs: &framework.DisplayAttributes{
						OperationSuffix: "roles",
					},
				},
			},
			HelpSynopsis:    pathRolesListHelpSyn,
			HelpDescription: pathRolesListHelpDesc,
		},
	}
}

func (b *hcpBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role := strings.ToLower(data.Get("role").(string))

	if role == "" {
		return logical.ErrorResponse("role is empty"), nil
	}

	if role != "admin" && role != "contributor" && role != "viewer" {
		return logical.ErrorResponse("role is invalid. Valid values: `Admin`, `Contributor`, `Viewer` "), nil
	}

	r := &hcpRole{
		Name: name,
		Role: role,
	}

	if ttl, ok := data.GetOk("ttl"); ok {
		r.TTL = time.Duration(ttl.(int)) * time.Second
	}

	if maxTTL, ok := data.GetOk("max_ttl"); ok {
		r.MaxTTL = time.Duration(maxTTL.(int)) * time.Second
	}

	if r.MaxTTL != 0 && r.TTL > r.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	entry, err := logical.StorageEntryJSON("roles/"+r.Name, r)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hcpBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "roles/"+data.Get("name").(string))
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

	return &logical.Response{
		Data: map[string]interface{}{
			"name":    role.Name,
			"role":    role.Role,
			"ttl":     role.TTL.Seconds(),
			"max_ttl": role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *hcpBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "roles/"+data.Get("name").(string))
	return nil, err
}

func (b *hcpBackend) pathRolesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

const pathRolesHelpSyn = `
Manages the Vault role for generating HashiCorp Cloud Platform (HCP) credentials
`

const pathRolesHelpDesc = `
This path allows you to read and write roles used to generate HashiCorp Cloud Platform (HCP) 
credentials. You can configure a role to manage a HCP service principal, and then 
generated service principal keys using the 'creds' endpoint.

A HashiCorp Cloud Platform service principal can only have two active keys.
`

const pathRolesListHelpSyn = `
List the existing roles on the HashiCorp Cloud Platform (HCP) backend
`

const pathRolesListHelpDesc = `
Roles will be listed by the role name
`
