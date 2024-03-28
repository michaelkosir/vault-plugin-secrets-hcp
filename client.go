package hcpsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"

	iam "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/client/iam_service"
	service_principals "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/client/service_principals_service"
	project "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/client/project_service"

	hcpClientConfig "github.com/hashicorp/hcp-sdk-go/config"
	"github.com/hashicorp/hcp-sdk-go/httpclient"
	"github.com/hashicorp/hcp-sdk-go/profile"
)

const hcpPluginUserAgent = "vault-plugin-secrets-hcp"

type hcpClient struct {
	IAM               iam.ClientService
	ServicePrincipals service_principals.ClientService
	Project           project.ClientService
}

func (b *hcpBackend) getClient(ctx context.Context, s logical.Storage) (*hcpClient, error) {
	if b.client != nil {
		return b.client, nil
	}

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = new(hcpConfig)
	}

	b.client, err = newClient(cfg)
	if err != nil {
		return nil, err
	}

	return b.client, nil
}

func newClient(cfg *hcpConfig) (*hcpClient, error) {
	hcpProfile := &profile.UserProfile{
		OrganizationID: cfg.OrganizationID,
		ProjectID:      cfg.ProjectID,
	}

	hcp, err := hcpClientConfig.NewHCPConfig(
		hcpClientConfig.WithClientCredentials(cfg.ClientID, cfg.ClientSecret),
		hcpClientConfig.WithProfile(hcpProfile),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid HCP config: %w", err)
	}

	// Fetch a token to verify that we have valid credentials
	if _, err := hcp.Token(); err != nil {
		return nil, fmt.Errorf("no valid credentials available: %w", err)
	}

	cl, err := httpclient.New(httpclient.Config{
		HCPConfig:     hcp,
		SourceChannel: hcpPluginUserAgent,
	})
	if err != nil {
		return nil, err
	}

	client := &hcpClient{
		IAM:               iam.New(cl, nil),
		ServicePrincipals: service_principals.New(cl, nil),
		Project:           project.New(cl, nil),
	}

	return client, nil
}
