package grafanacloud

import (
	"context"
	"fmt"

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
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Grafana Cloud API token",
			},
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the API Token",
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
	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = lease.TTL
	resp.Secret.MaxTTL = lease.MaxTTL
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

	name, ok := req.Secret.InternalData["name"]
	if !ok {
		return nil, fmt.Errorf("name is missing on the lease")
	}

	b.Logger().Info(fmt.Sprintf("Revoking grafana-cloud token (%s)...", name))
	err = c.DeleteToken(name.(string))
	if err != nil {
		return nil, err
	}

	return nil, nil
}
