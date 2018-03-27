package josejwt

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var configURLsSchema = map[string]*framework.FieldSchema{
	"base_url": {
		Type:        framework.TypeString,
		Description: "The base URL to set on 'jku' claims.",
	},
}

func pathConfigURLs(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      "config/urls",
			Fields:       configURLsSchema,
			HelpSynopsis: "Sets the URL settings.",
			HelpDescription: `
This path allows you to set the base URL used to construct references to keys.
			`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.pathUpdateConfigURLs,
				logical.ReadOperation:   backend.pathReadConfigURLs,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) pathUpdateConfigURLs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	if baseURL, ok := data.GetOk("base_url"); ok {
		config.BaseURL = baseURL.(string)
	}

	if err = writeConfig(ctx, req, config); err != nil {
		return logical.ErrorResponse("err writing config"), err
	}

	return &logical.Response{Data: map[string]interface{}{
		"base_url": config.BaseURL,
	}}, nil
}

func (backend *JwtBackend) pathReadConfigURLs(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	return &logical.Response{Data: map[string]interface{}{
		"base_url": config.BaseURL,
	}}, nil
}
