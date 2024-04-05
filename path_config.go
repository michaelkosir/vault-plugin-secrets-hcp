package hcpsecrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type hcpConfig struct {
	OrganizationID string `json:"organization"`
	ProjectID      string `json:"project"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
}

func (b *hcpBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefix,
		},
		Fields: map[string]*framework.FieldSchema{
			"organization": {
				Type:        framework.TypeLowerCaseString,
				Description: "HCP organization ID that contains the projects of the resources",
				Required:    true,
			},
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "HCP project ID that contains the resources",
				Required:    true,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "Service principal client ID used to authenticate to HCP",
				Required:    true,
			},
			"client_secret": {
				Type:        framework.TypeString,
				Description: "Service principal client secret used to authenticate to HCP",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.PatchOperation: &framework.PathOperation{
				Callback: b.pathConfigPatch,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
		},
		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *hcpBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	organizationID := data.Get("organization").(string)
	if organizationID == "" {
		return nil, errors.New("organization is empty")
	}

	projectID := data.Get("project").(string)
	if projectID == "" {
		return nil, errors.New("project is empty")
	}

	clientID := data.Get("client_id").(string)
	if clientID == "" {
		return nil, errors.New("client_id is empty")
	}

	clientSecret := data.Get("client_secret").(string)
	if clientSecret == "" {
		return nil, errors.New("client_secret is empty")
	}

	cfg := &hcpConfig{
		OrganizationID: organizationID,
		ProjectID:      projectID,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
	}

	if err := saveConfig(ctx, req.Storage, cfg); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hcpBackend) pathConfigPatch(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg := &hcpConfig{
		OrganizationID: data.Get("organization").(string),
		ProjectID:      data.Get("project").(string),
		ClientID:       data.Get("client_id").(string),
		ClientSecret:   data.Get("client_secret").(string),
	}

	if err := patchConfig(ctx, req, cfg); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *hcpBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = new(hcpConfig)
	}

	// do not include `client_secret` in response
	return &logical.Response{
		Data: map[string]interface{}{
			"organization": cfg.OrganizationID,
			"project":      cfg.ProjectID,
			"client_id":    cfg.ClientID,
		},
	}, nil
}

func (b *hcpBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")
	return nil, err
}

func getConfig(ctx context.Context, s logical.Storage) (*hcpConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, errors.New("error retrieving config: config is nil")
	}

	cfg := new(hcpConfig)
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	return cfg, nil
}

func saveConfig(ctx context.Context, s logical.Storage, cfg *hcpConfig) error {
	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func patchConfig(ctx context.Context, req *logical.Request, patch *hcpConfig) error {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}

	if patch.OrganizationID != "" {
		cfg.OrganizationID = patch.OrganizationID
	}

	if patch.ProjectID != "" {
		cfg.ProjectID = patch.ProjectID
	}

	if patch.ClientID != "" {
		cfg.ClientID = patch.ClientID
	}

	if patch.ClientSecret != "" {
		cfg.ClientSecret = patch.ClientSecret
	}

	if err := saveConfig(ctx, req.Storage, cfg); err != nil {
		return err
	}

	return nil
}

const pathConfigHelpSyn = `
Configure the initial connection to the HashiCorp Cloud Platform.
`

const pathConfigHelpDesc = `
The HashiCorp Cloud Platform (HCP) secrets engine can create service principals
and service principal keys at either the Organization or Project level. A configuration
of the engine represents a single HCP Organization or Project.
`
