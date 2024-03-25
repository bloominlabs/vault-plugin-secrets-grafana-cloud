package grafanacloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	SecretTokenType = "token"
)

func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "Grafana Cloud API token",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the API Token",
			},
			"id": {
				Type:        framework.TypeString,
				Description: "ID of the API Token",
			},
			"access_policy_id": {
				Type:        framework.TypeString,
				Description: "ID of the Access Policy the token belongs to",
			},
		},

		Renew:  b.secretTokenRenew,
		Revoke: b.secretTokenRevoke,
	}
}

func (b *backend) secretTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	lease, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, _, err := framework.CalculateTTL(b.System(), 0, lease.TTL, 0, lease.MaxTTL, 0, time.Time{})
	if err != nil {
		return logical.ErrorResponse("failed to calculate ttl. err: %w", err), nil
	}

	id, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("id is missing on the lease")
	}

	err = c.UpdateToken(id.(string), time.Now().UTC().Add(ttl))
	if err != nil {
		return nil, fmt.Errorf("failed to update token %s: %w", id.(string), err)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = lease.MaxTTL
	resp.Secret.Renewable = false
	return resp, nil
}

func (b *backend) secretTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if c == nil {
		return nil, fmt.Errorf("error getting Nomad client")
	}

	id, ok := req.Secret.InternalData["id"]
	if !ok {
		return nil, fmt.Errorf("id is missing on the lease")
	}

	name, ok := req.Secret.InternalData["name"]
	if !ok {
		return nil, fmt.Errorf("name is missing on the lease")
	}

	b.Logger().Info(fmt.Sprintf("Revoking grafana-cloud token (name: %s, id: %s)...", name, id))
	err = c.DeleteToken(id.(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}
