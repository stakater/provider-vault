/*
Copyright 2021 Upbound Inc.
*/

package clients

import (
	"context"
	"encoding/json"

	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/upbound/upjet/pkg/terraform"

	"github.com/stakater/provider-vault/apis/v1beta1"
)

const (
	// error messages
	errNoProviderConfig     = "no providerConfigRef provided"
	errGetProviderConfig    = "cannot get referenced ProviderConfig"
	errTrackUsage           = "cannot track ProviderConfig usage"
	errExtractCredentials   = "cannot extract credentials"
	errUnmarshalCredentials = "cannot unmarshal vault credentials as JSON"
)

// TerraformSetupBuilder builds Terraform a terraform.SetupFn function which
// returns Terraform provider setup configuration
func TerraformSetupBuilder(version, providerSource, providerVersion string) terraform.SetupFn {
	return func(ctx context.Context, client client.Client, mg resource.Managed) (terraform.Setup, error) {
		ps := terraform.Setup{
			Version: version,
			Requirement: terraform.ProviderRequirement{
				Source:  providerSource,
				Version: providerVersion,
			},
		}

		configRef := mg.GetProviderConfigReference()
		if configRef == nil {
			return ps, errors.New(errNoProviderConfig)
		}
		pc := &v1beta1.ProviderConfig{}
		if err := client.Get(ctx, types.NamespacedName{Name: configRef.Name}, pc); err != nil {
			return ps, errors.Wrap(err, errGetProviderConfig)
		}

		t := resource.NewProviderConfigUsageTracker(client, &v1beta1.ProviderConfigUsage{})
		if err := t.Track(ctx, mg); err != nil {
			return ps, errors.Wrap(err, errTrackUsage)
		}

		data, err := resource.CommonCredentialExtractor(ctx, pc.Spec.Credentials.Source, client, pc.Spec.Credentials.CommonCredentialSelectors)
		if err != nil {
			return ps, errors.Wrap(err, errExtractCredentials)
		}
		creds := map[string]string{}
		if err := json.Unmarshal(data, &creds); err != nil {
			return ps, errors.Wrap(err, errUnmarshalCredentials)
		}

		// Set credentials in Terraform provider configuration.
		ps.Configuration = map[string]any{
			"address": creds["address"],
			"add_address_to_env": creds["add_address_to_env"],
			"token": creds["token"],
			"token_name": creds["token_name"],
			"ca_cert_file": creds["ca_cert_file"],
			"ca_cert_dir": creds["ca_cert_dir"],
			"auth_login_userpass": creds["auth_login_userpass"],
			"auth_login_aws": creds["auth_login_aws"],
			"auth_login_cert": creds["auth_login_cert"],
			"auth_login_gcp": creds["auth_login_gcp"],
			"auth_login_kerberos": creds["auth_login_kerberos"],
			"auth_login_radius": creds["auth_login_radius"],
			"auth_login_oci": creds["auth_login_oci"],
			"auth_login_oidc": creds["auth_login_oidc"],
			"auth_login_jwt": creds["auth_login_jwt"],
			"auth_login_azure": creds["auth_login_azure"],
			"auth_login_token_file": creds["auth_login_token_file"],
			"auth_login": creds["auth_login"],
			"client_auth": creds["client_auth"],
			"skip_tls_verify": creds["skip_tls_verify"],
			"tls_server_name": creds["tls_server_name"],
			"skip_child_token": creds["skip_child_token"],
			"max_lease_ttl_seconds": creds["max_lease_ttl_seconds"],
			"max_retries": creds["max_retries"],
			"max_retries_ccc": creds["max_retries_ccc"],
			"namespace": creds["namespace"],
			"skip_get_vault_version": creds["skip_get_vault_version"],
			"vault_version_override": creds["vault_version_override"],

		}
		return ps, nil
	}
}
