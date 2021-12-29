package grafanacloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type GrafanaToken struct {
	K  string `json:"k"`
	N  string `json:"n"`
	ID int    `json:"id"`
}

func decodeToken(token string) (GrafanaToken, error) {
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return GrafanaToken{}, err
	}

	var grafanaToken GrafanaToken
	if err := json.Unmarshal(decodedToken, &grafanaToken); err != nil {
		return GrafanaToken{}, err
	}

	return grafanaToken, nil
}

const configTokenKey = "config/token"

func pathConfigToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/token",
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Token for API calls",
			},
			"orgSlug": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Organization Slug the API token belongs to",
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
		return nil, errwrap.Wrapf("error reading nomad access configuration: {{err}}", err)
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
			"token":   conf.Token,
			"orgSlug": conf.OrganizationSlug,
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

	orgSlug, ok := data.GetOk("orgSlug")
	if !ok {
		missingOptions = append(missingOptions, "orgSlug")
	} else {
		conf.OrganizationSlug = orgSlug.(string)
	}

	if len(missingOptions) > 0 {
		return logical.ErrorResponse("Missing %s in configuration request", strings.Join(missingOptions, ",")), nil
	}

	decodedToken, err := decodeToken(conf.Token)
	if err != nil {
		return logical.ErrorResponse("failed to decoded token (%s). please check that token is valid", conf.Token), nil
	}

	entry, err := logical.StorageEntryJSON(configTokenKey, conf)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	client, err := b.client(ctx, req.Storage)
	if err != nil {
		req.Storage.Delete(ctx, configTokenKey)
		return nil, err
	}

	tokenName := decodedToken.N
	foundToken, err := client.findToken(tokenName)
	if err != nil {
		req.Storage.Delete(ctx, configTokenKey)
		s, ok := err.(GrafanaAPIError)
		if ok {
			return logical.ErrorResponse(fmt.Sprintf("err while listing token from grafana cloud. code: %s, err: %s", s.Code, s.Message)), nil
		}
		return nil, err
	}

	if foundToken != nil && foundToken.Role == adminSlug {
		return nil, nil
	}

	req.Storage.Delete(ctx, configTokenKey)
	return logical.ErrorResponse(fmt.Sprintf("Could not find token '%s' with permission '%s' in Grafana Cloud", tokenName, adminSlug)), nil
}

func (b *backend) pathConfigTokenDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configTokenKey); err != nil {
		return nil, err
	}
	return nil, nil
}

type accessTokenConfig struct {
	Token            string `json:"token"`
	OrganizationSlug string `json:"orgSlug"`
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
