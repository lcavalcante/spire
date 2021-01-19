package azure

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	uuid "github.com/satori/go.uuid"
	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "azure_keyvault"
)

type secret struct {
	name     string
	group    string
	location string
	tenantID string
	vault    string
}

func BuiltIn() catalog.Plugin {
	return builtin(New())
}

func builtin(p *KeyVaultPlugin) catalog.Plugin {
	return catalog.MakePlugin(pluginName, svidstore.PluginServer(p))
}

func New() *KeyVaultPlugin {
	return &KeyVaultPlugin{}
}

type Config struct {
	Location       string `hcl:"locations"`
	ResourceGroup  string `hcl:"resource_group"`
	SubscriptionID string `hcl:"subscription_id"`
	TenantID       string `hcl:"tenant_id"`
}

type KeyVaultPlugin struct {
	svidstore.UnsafeSVIDStoreServer

	log    hclog.Logger
	config *Config
	mtx    sync.RWMutex
}

func (p *KeyVaultPlugin) SetLogger(log hclog.Logger) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.log = log
}

// Configure configures the KeyVaultPlugin.
func (p *KeyVaultPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	// Parse HCL config payload into config struct
	config := &Config{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.SubscriptionID == "" {
		return nil, status.Error(codes.InvalidArgument, "`subscription_id` is required")
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config

	return &spi.ConfigureResponse{}, nil
}

// GetPluginInfo returns the version and other metadata of the plugin.
func (*KeyVaultPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

// PutX509SVID puts the specified X509-SVID in the configured Azure Key Vault
func (p *KeyVaultPlugin) PutX509SVID(ctx context.Context, req *svidstore.PutX509SVIDRequest) (*svidstore.PutX509SVIDResponse, error) {
	s := p.parseSelectors(req.Selectors)

	switch {
	case s.name == "":
		return nil, status.Error(codes.InvalidArgument, "secret name is required")
	case s.group == "":
		return nil, status.Error(codes.InvalidArgument, "secret group name is required")
	case s.tenantID == "":
		return nil, status.Error(codes.InvalidArgument, "secret tenant ID is required")
	case s.vault == "":
		return nil, status.Error(codes.InvalidArgument, "secret vault is required")
	}

	// Verify if vault exists, create it if necessary
	if err := p.verifyVaulExists(ctx, s); err != nil {
		return nil, err
	}

	// Add new secret to Key Vault
	if err := p.setSecret(ctx, req, s); err != nil {
		return nil, err
	}

	return &svidstore.PutX509SVIDResponse{}, nil
}

// setSecret adds a new SVID as a secret an specified Key Vault
func (p *KeyVaultPlugin) setSecret(ctx context.Context, req *svidstore.PutX509SVIDRequest, s *secret) error {
	client, err := createServiceVaultClient()
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create client: %v", err)
	}

	secretBinary, err := svidstore.EncodeSecret(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to encode sercret: %v", err)
	}

	// TODO: add var for vautl name and another for secret name
	vaultURI := fmt.Sprintf("https://%s.%s/", s.name, azure.PublicCloud.KeyVaultDNSSuffix)
	resp, err := client.SetSecret(ctx, vaultURI, s.name, kv.SecretSetParameters{
		Value:       to.StringPtr(string(secretBinary)),
		ContentType: to.StringPtr("X509-SVID"),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to set secret: %v", err)
	}

	p.log.With("status", resp.Status, "name", s.name).Info("Set secret")

	return nil
}

// verifyVaulExists verify if Key Vault exists and it contains 'spire-svid' tag.
// If not exists a new Key Vault is created
func (p *KeyVaultPlugin) verifyVaulExists(ctx context.Context, s *secret) error {
	client, err := createMgmtVaultClient(p.config.SubscriptionID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create management vault client: %v", err)
	}

	// response contains datails about `error` when call fails.
	getResp, err := client.Get(ctx, s.group, s.vault)
	switch getResp.StatusCode {
	case http.StatusOK:
		p.log.With("vault", getResp.Name).Debug("key vault found")
		if !validateTag(getResp.Tags) {
			return status.Errorf(codes.InvalidArgument, "key vault %q does not contains 'spire-svid' tag", s.vault)
		}

		return nil
	case http.StatusNotFound:
		p.log.With("vault", s.vault).Debug("key vault not found, creating...")
	default:
		return status.Errorf(codes.Internal, "failed to get key vault %q: %v", s.vault, err)
	}

	if s.location == "" {
		return status.Error(codes.InvalidArgument, "location is required to create key vault")
	}

	tenantID, err := uuid.FromString(s.tenantID)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "malformed tenant ID: %v", err)
	}

	// Get current user ID, it is required to create an access policy to allow current user to  get and set secrets.
	userID, err := p.getCurrentUser(ctx, s.tenantID)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get current user: %v", err)
	}

	properties := &keyvault.VaultProperties{
		TenantID: &tenantID,
		Sku: &keyvault.Sku{
			Family: to.StringPtr("A"),
			Name:   keyvault.Standard,
		},
		AccessPolicies: &[]keyvault.AccessPolicyEntry{
			{
				ObjectID: userID,
				TenantID: &tenantID,
				Permissions: &keyvault.Permissions{
					Secrets: &[]keyvault.SecretPermissions{
						// Get and List are not required, added them to verify they exists on UI
						keyvault.SecretPermissionsGet,
						keyvault.SecretPermissionsSet,
						keyvault.SecretPermissionsList,
					},
				},
			},
		},
	}

	_, err = client.CreateOrUpdate(ctx, s.group, s.vault, keyvault.VaultCreateOrUpdateParameters{
		Location:   &s.location,
		Tags:       map[string]*string{"spire-svid": to.StringPtr("true")},
		Properties: properties,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return nil
}

// Get current user ID.
func (p *KeyVaultPlugin) getCurrentUser(ctx context.Context, tenantID string) (*string, error) {
	client, err := createSignedInUserClient(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Auth: %v", err)
	}

	user, err := client.Get(ctx)
	if err != nil {
		return nil, err
	}

	return user.ObjectID, nil
}

// parseSelectors parse selectors into 'secret', and set default values if required
func (p *KeyVaultPlugin) parseSelectors(selectors []*common.Selector) *secret {
	data := svidstore.ParseSelectors(selectors)
	name := data["secretname"]
	vault := data["secretvault"]

	group := p.config.ResourceGroup
	if value, ok := data["secretgroup"]; ok {
		group = value
	}

	tenantID := p.config.TenantID
	if value, ok := data["secrettenantid"]; ok {
		tenantID = value
	}

	location := p.config.Location
	if value, ok := data["secretlocation"]; ok {
		location = value
	}

	return &secret{
		name:     name,
		group:    group,
		location: location,
		tenantID: tenantID,
		vault:    vault,
	}
}

// validateTag validates that tags contains 'spire-svid' and it is 'true'
func validateTag(tags map[string]*string) bool {
	spireLabel, ok := tags["spire-svid"]
	return ok && *spireLabel == "true"
}
