package grafanacloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configTokenKey = "config/token"

func pathConfigToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/token",
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Token for API calls",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathConfigTokenRead,
			logical.CreateOperation: b.pathConfigTokenWrite,
			logical.UpdateOperation: b.pathConfigTokenWrite,
			logical.DeleteOperation: b.pathConfigTokenDelete,
		},

		ExistenceCheck: b.configTokenExistenceCheck,
	}
}

func (b *backend) configTokenExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

func (b *backend) readConfigToken(ctx context.Context, storage logical.Storage) (*accessTokenConfig, error) {
	entry, err := storage.Get(ctx, configTokenKey)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	conf := &accessTokenConfig{}
	if err := entry.DecodeJSON(conf); err != nil {
		return nil, fmt.Errorf("error reading nomad access configuration: %w", err)
	}

	return conf, nil
}

func (b *backend) pathConfigTokenRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		return logical.ErrorResponse("configuration does not exist. did you configure 'config/token'?"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token":          conf.Token,
			"id":             conf.TokenID,
			"accessPolicyID": conf.AccessPolicyID,
		},
	}, nil
}

func (b *backend) pathConfigTokenWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	conf, err := b.readConfigToken(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		conf = &accessTokenConfig{}
	}

	var missingOptions []string
	token, ok := data.GetOk("token")
	if !ok {
		missingOptions = append(missingOptions, "token")
	} else {
		conf.Token = token.(string)
	}
	if len(missingOptions) > 0 {
		return logical.ErrorResponse("Missing %s in configuration request", strings.Join(missingOptions, ",")), nil
	}

	client, err := createClient(conf.Token)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create client: %s", err)), nil
	}

	decodedToken, err := DecodeToken(conf.Token)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to decode token: %s", err)), nil
	}

	resp, err := client.GetTokenByName(decodedToken.TokenName)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to get token: %s", err)), nil
	}
	conf.AccessPolicyID = resp.AccessPolicyID
	conf.TokenID = resp.ID

	entry, err := logical.StorageEntryJSON(configTokenKey, conf)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigTokenDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configTokenKey); err != nil {
		return nil, err
	}
	return nil, nil
}

type accessTokenConfig struct {
	TokenID        string `json:"id"`
	Token          string `json:"token"`
	AccessPolicyID string `json:"access_policy_id"`
}

const pathConfigTokenHelpSyn = `
Configure Grafana Cloud token and options used by vault
`

const pathConfigTokenHelpDesc = `
Will confugre this mount with the token, token name, and organization slug used
by Vault for all Grafana Cloud operations on this mount. Must be configured
with an 'Admin' token.

For instructions on how to get and/or create a Grafana Cloud 'Admin' token
and token name, see their documentation at
https://grafana.com/docs/grafana-cloud/cloud-portal/create-api-key/. The
organization slug can be found by logging into your stack and looking at the
url, e.g. https://grafana.com/orgs/{orgSlug}.
`
