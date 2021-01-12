package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/latest/keyvault/mgmt/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

func createMgmtVaultClient(subscriptionID string) (*keyvault.VaultsClient, error) {
	auth, err := auth.NewAuthorizerFromCLI()
	if err != nil {
		return nil, err
	}

	client := keyvault.NewVaultsClient(subscriptionID)
	client.Authorizer = auth

	return &client, nil
}

func createServiceVaultClient() (*kv.BaseClient, error) {
	// TODO: there are several mechanism to authenticate against azure API (https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization)
	// client authorization was choosed for POC test simplificaton
	// AUDIENCE `https://vault.azure.net` is required, it is possible to use `AZURE_AD_RESOURCE` to specify it.
	authorizer, err := auth.NewAuthorizerFromCLIWithResource("https://vault.azure.net")
	if err != nil {
		return nil, err
	}

	client := kv.New()
	client.Authorizer = authorizer

	return &client, nil
}

func createSignedInUserClient(tenantID string) (*graphrbac.SignedInUserClient, error) {
	// // Get graph endpoint
	// envSettings, err := auth.GetSettingsFromEnvironment()
	// if err != nil {
	// return nil, err
	// }
	// env := envSettings.Environment
	// graphEndpoint = env.GraphEndpoint

	// TODO: An alternative to hardcoded resource is to get resourses form env var (https://docs.microsoft.com/en-us/dotnet/api/microsoft.azure.management.resourcemanager.fluent.azureenvironment.graphendpoint?view=azure-dotnet)
	authorizer, err := auth.NewAuthorizerFromCLIWithResource("https://graph.windows.net/")
	if err != nil {
		return nil, fmt.Errorf("failed to get Auth: %v", err)
	}

	client := graphrbac.NewSignedInUserClient(tenantID)
	client.Authorizer = authorizer

	return &client, nil
}
