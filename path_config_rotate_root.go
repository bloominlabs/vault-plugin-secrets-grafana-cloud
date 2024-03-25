package grafanacloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfigRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigRotateRootUpdate,
			},
		},

		HelpSynopsis:    pathConfigRotateRootHelpSyn,
		HelpDescription: pathConfigRotateRootHelpDesc,
	}
}

func (b *backend) pathConfigRotateRootUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("rotating root token")
	// have to get the client config first because that takes out a read lock
	client, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("nil client")
	}

	currentToken, err := req.Storage.Get(ctx, configTokenKey)
	if err != nil {
		return nil, err
	}
	if currentToken == nil {
		return nil, fmt.Errorf("no configuration found for config/token")
	}
	var currentConfig accessTokenConfig
	if err := currentToken.DecodeJSON(&currentConfig); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	if currentConfig.AccessPolicyID == "" || currentConfig.Token == "" {
		return logical.ErrorResponse("Cannot call config/rotate-root when either accessPolicyID or token is empty"), nil
	}

	name := fmt.Sprintf("vault-mount-config-%d", time.Now().UnixNano())
	createTokenRequest := CreateTokenRequest{
		AccessPolicyID: currentConfig.AccessPolicyID,
		Name:           name,
		DisplayName:    "grafana cloud vault mount",
		ExpiresAt:      time.Now().UTC().Add(time.Hour * 24 * 90),
	}
	newToken, err := client.CreateToken(createTokenRequest)
	if err != nil {
		return nil, err
	}
	b.Logger().Info("token", "newToken", newToken)

	newConfig := accessTokenConfig{
		TokenID:        newToken.ID,
		Token:          newToken.Token,
		AccessPolicyID: newToken.AccessPolicyID,
	}

	newEntry, err := logical.StorageEntryJSON(configTokenKey, newConfig)
	if err != nil {
		return nil, fmt.Errorf("error generating new config/root JSON: %w", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, fmt.Errorf("error saving new config/root: %w", err)
	}

	err = client.DeleteToken(currentConfig.TokenID)
	if err != nil {
		return nil, fmt.Errorf("error deleting old access key: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":            newConfig.TokenID,
			"accesPolicyID": newConfig.AccessPolicyID,
		},
	}, nil
}

const pathConfigRotateRootHelpSyn = `
Request to rotate the Grafana Cloud token used by Vault
`

const pathConfigRotateRootHelpDesc = `
This path attempts to rotate the Grafana Cloud credentials used by Vault for this mount.
It is only valid if Vault has been configured to use Admin Grafana CLoud token via the
config/token endpoint.
`
