package grafanacloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend
}

var _ logical.Factory = Factory

const adminSlug string = "Admin"

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := newBackend()
	if err != nil {
		return nil, err
	}

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}

	return b, nil
}

func newBackend() (*backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(mockHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			b.paths(),
		),
		Secrets: []*framework.Secret{
			secretToken(b),
		},
	}

	return b, nil
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		pathConfigToken(b),
		pathCredCreate(b),
		pathConfigRotateRoot(b),
		pathConfigLease(b),
		pathListAccessPolicies(b),
		pathAccessPolicies(b),
	}
}

const mockHelp = `
	Generates grafana cloud access tokens using access policies.
`
