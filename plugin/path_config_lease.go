package josejwt

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var configLeaseSchema = map[string]*framework.FieldSchema{
	"lease": {
		Type:        framework.TypeDurationSecond,
		Description: "The default token TTL for roles that create JWTs.",
	},
	"lease_max": {
		Type:        framework.TypeDurationSecond,
		Description: "The default max token TTL for roles that create JWTs.",
	},
}

// set up the paths for the roles within vault
func pathConfigLease(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      "config/lease",
			Fields:       configLeaseSchema,
			HelpSynopsis: "Sets the lease defaults for the plugin.",
			HelpDescription: `
This path allows you to set the defaults used in roles.
			`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.pathUpdateConfigLease,
				logical.ReadOperation:   backend.pathReadConfigLease,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) pathUpdateConfigLease(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	if tokenTTL, ok := data.Get("lease").(int); ok {
		config.Lease = time.Second * time.Duration(tokenTTL)
	}

	if tokenTTL, ok := data.Get("lease_max").(int); ok {
		config.LeaseMax = time.Second * time.Duration(tokenTTL)
	}

	if err = writeConfig(ctx, req, config); err != nil {
		return logical.ErrorResponse("err writing config"), err
	}

	return &logical.Response{Data: config.toLeaseMap()}, nil
}

func (backend *JwtBackend) pathReadConfigLease(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	return &logical.Response{Data: config.toLeaseMap()}, nil
}

func getDurationOrDefault(data *framework.FieldData, key string, d time.Duration) time.Duration {
	if t, ok := data.GetOk(key); ok {
		return time.Second * time.Duration(t.(int))
	}
	return d
}
