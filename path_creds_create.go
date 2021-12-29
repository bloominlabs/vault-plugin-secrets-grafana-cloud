package grafanacloud

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// maxTokenNameLength is the maximum length for the name of a Nomad access
// token
const maxTokenNameLength = 256

func pathCredCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Permission level of API key. One of 'Viewer', 'Editor', 'Admin', or 'MetricsPublisher'",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredRead,
		},
	}
}

func (b *backend) pathCredRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role := d.Get("role").(string)

	// Get the http client
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	lease, err := b.LeaseConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if lease == nil {
		lease = &configLease{}
	}

	// Create it
	b.Logger().Info(fmt.Sprintf("creating grafana-cloud token (role: %s)...", role))
	token, err := c.CreateToken(createTokenName(role), role)
	if err != nil {
		s, ok := err.(GrafanaAPIError)
		if ok {
			return logical.ErrorResponse(fmt.Sprintf("err while creating token with role '%s' from grafana cloud. code: %s, err: %s", role, s.Code, s.Message)), nil
		}
		return nil, err
	}

	// Use the helper to create the secret
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"token": token.Token,
		"name":  token.Name,
	}, map[string]interface{}{
		"token": token.Token,
		"name":  token.Name,
	})
	resp.Secret.TTL = lease.TTL
	resp.Secret.MaxTTL = lease.MaxTTL

	return resp, nil
}
