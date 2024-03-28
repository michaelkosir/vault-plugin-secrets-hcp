package hcpsecrets

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	models "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/models"
	resourcemodels "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/models"
	"github.com/hashicorp/vault/sdk/logical"

	iam "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/client/iam_service"
	service_principals "github.com/hashicorp/hcp-sdk-go/clients/cloud-iam/stable/2019-12-10/client/service_principals_service"
	project "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/client/project_service"
)

func createServicePrincipal(ctx context.Context, req *logical.Request, cl *hcpClient, role string) (*models.HashicorpCloudIamServicePrincipal, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	// service principal name template
	name := fmt.Sprintf("v-%s-%03d-%d", role, rand.Intn(1000), time.Now().Unix())
	if len(name) > 36 {
		name = name[:36]
	}

	p := service_principals.NewServicePrincipalsServiceCreateServicePrincipalParams()
	p.Body.Name = name
	p.ParentResourceName = "project/" + cfg.ProjectID

	r, err := cl.ServicePrincipals.ServicePrincipalsServiceCreateServicePrincipal(p, nil)
	if err != nil {
		return nil, err
	}

	return r.Payload.ServicePrincipal, nil
}

func createServicePrincipalKey(cl *hcpClient, s *models.HashicorpCloudIamServicePrincipal) (*models.HashicorpCloudIamCreateServicePrincipalKeyResponse, error) {
	p := service_principals.NewServicePrincipalsServiceCreateServicePrincipalKeyParams()
	p.ParentResourceName = s.ResourceName

	r, err := cl.ServicePrincipals.ServicePrincipalsServiceCreateServicePrincipalKey(p, nil)
	if err != nil {
		return nil, err
	}

	return r.Payload, nil
}

func deleteServicePrincipal(cl *hcpClient, sp *models.HashicorpCloudIamServicePrincipal) error {
	p := service_principals.NewServicePrincipalsServiceDeleteServicePrincipalParams()
	p.ResourceName = sp.ResourceName
	if _, err := cl.ServicePrincipals.ServicePrincipalsServiceDeleteServicePrincipal(p, nil); err != nil {
		return err
	}
	return nil
}

func deleteServicePrincipalKey(cl *hcpClient, spk *models.HashicorpCloudIamServicePrincipalKey) error {
	p := service_principals.NewServicePrincipalsServiceDeleteServicePrincipalKeyParams()
	p.ResourceName2 = spk.ResourceName

	if _, err := cl.ServicePrincipals.ServicePrincipalsServiceDeleteServicePrincipalKey(p, nil); err != nil {
		return err
	}

	return nil
}

// returns the current Service Principal and Service Principal Key used by the plugin
func getCallerIdentity(ctx context.Context, req *logical.Request, cl *hcpClient) (*models.HashicorpCloudIamServicePrincipal, *models.HashicorpCloudIamServicePrincipalKey, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, nil, err
	}

	// get current service principal
	pGCI := iam.NewIamServiceGetCallerIdentityParams()
	rGCI, err := cl.IAM.IamServiceGetCallerIdentity(pGCI, nil)
	if err != nil {
		return nil, nil, err
	}

	// get all keys owned by service principal
	pGSP := service_principals.NewServicePrincipalsServiceGetServicePrincipalParams()
	pGSP.ResourceName = rGCI.Payload.Principal.Service.ResourceName
	rGSP, err := cl.ServicePrincipals.ServicePrincipalsServiceGetServicePrincipal(pGSP, nil)
	if err != nil {
		return nil, nil, err
	}

	// find the key matching the config's ClientID
	var currentKey *models.HashicorpCloudIamServicePrincipalKey = nil
	for _, key := range rGSP.Payload.Keys {
		if key.ClientID == cfg.ClientID {
			currentKey = key
			break
		}
	}

	if currentKey == nil {
		return nil, nil, fmt.Errorf("error finding current service princpal key")
	}

	return rGCI.Payload.Principal.Service, currentKey, nil
}

func assignServicePrincipalRole(ctx context.Context, req *logical.Request, cl *hcpClient, sp *models.HashicorpCloudIamServicePrincipal, role string) error {
	roleID := "roles/" + role

	policy, err := getIAMPolicy(ctx, req, cl)
	if err != nil {
		return err
	}

	member := &resourcemodels.HashicorpCloudResourcemanagerPolicyBindingMember{
		MemberType: resourcemodels.HashicorpCloudResourcemanagerPolicyBindingMemberTypeSERVICEPRINCIPAL.Pointer(),
		MemberID:   sp.ID,
	}

	// iterate through policy to find appropriate role
	// add service principal to role
	found := false
	for i, binding := range policy.Bindings {
		if binding.RoleID == roleID {
			found = true
			policy.Bindings[i].Members = append(policy.Bindings[i].Members, member)
			break
		}
	}

	if !found {
		// role does not exist in current policy
		// this means its the first service principal for the role
		binding := new(resourcemodels.HashicorpCloudResourcemanagerPolicyBinding)
		binding.RoleID = roleID
		binding.Members = append(binding.Members, member)

		policy.Bindings = append(policy.Bindings, binding)
	}

	if err := setIAMPolicy(ctx, req, cl, policy); err != nil {
		return err
	}

	return nil
}

func getIAMPolicy(ctx context.Context, req *logical.Request, cl *hcpClient) (*resourcemodels.HashicorpCloudResourcemanagerPolicy, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	p := project.NewProjectServiceGetIamPolicyParams()
	p.ID = cfg.ProjectID

	r, err := cl.Project.ProjectServiceGetIamPolicy(p, nil)
	if err != nil {
		return nil, err
	}

	return r.Payload.Policy, nil
}

func setIAMPolicy(ctx context.Context, req *logical.Request, cl *hcpClient, policy *resourcemodels.HashicorpCloudResourcemanagerPolicy) error {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return err
	}

	p := project.NewProjectServiceSetIamPolicyParams()
	p.ID = cfg.ProjectID
	p.Body.Policy = policy

	if _, err := cl.Project.ProjectServiceSetIamPolicy(p, nil); err != nil {
		return err
	}

	return nil
}
