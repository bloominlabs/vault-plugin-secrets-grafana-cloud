package grafanacloud

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// maxTokenNameLength is the maximum length for the name of a Nomad access
// token
const maxTokenNameLength = 256

func pathCredCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the access policy to generate a key for",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredRead,
		},
	}
}

func (b *backend) pathCredRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

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

	policy, err := b.accessPoliciesRead(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to read access policy '%s': %s", name, err)), nil
	}
	if policy == nil {
		return logical.ErrorResponse(fmt.Sprintf("did not file access policy '%s'", name)), nil
	}

	ttl, _, err := framework.CalculateTTL(b.System(), 0, lease.TTL, 0, lease.MaxTTL, 0, time.Time{})
	if err != nil {
		return logical.ErrorResponse("failed to calculate ttl. err: %w", err), nil
	}

	// Create it
	b.Logger().Info(fmt.Sprintf("creating grafana-cloud token (policy: %s)...", name))
	tokenName := createTokenName(name)
	token, err := c.CreateToken(CreateTokenRequest{
		AccessPolicyID: policy.Policy.ID,
		Name:           tokenName,
		DisplayName:    tokenName,
		ExpiresAt:      time.Now().UTC().Add(ttl),
	})
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("err while creating token with role '%s' from grafana cloud. err: %s", name, err)), nil
	}

	// Use the helper to create the secret
	resp := b.Secret(SecretTokenType).Response(map[string]interface{}{
		"id":               token.ID,
		"access_policy_id": token.AccessPolicyID,
		"token":            token.Token,
		"name":             token.Name,
	}, map[string]interface{}{
		"id":               token.ID,
		"access_policy_id": token.AccessPolicyID,
		"token":            token.Token,
		"name":             token.Name,
	})
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = lease.MaxTTL
	resp.Secret.Renewable = false

	return resp, nil
}
