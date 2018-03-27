package josejwt

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

var configSchema = map[string]*framework.FieldSchema{
	"default_token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The default token TTL for roles that create JWTs.",
	},
	"default_max_token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The default max token TTL for roles that create JWTs.",
	},
}

type configStorageEntry struct {
	DefaultTokenTTL    time.Duration `json:"default_token_ttl" structs:"default_token_ttl" mapstructure:"default_token_ttl"`
	DefaultMaxTokenTTL time.Duration `json:"default_max_token_ttl" structs:"default_max_token_ttl" mapstructure:"default_max_token_ttl"`
}

func (c *configStorageEntry) toMap() map[string]interface{} {
	return map[string]interface{}{
		"default_token_ttl":     c.DefaultTokenTTL.Seconds(),
		"default_max_token_ttl": c.DefaultMaxTokenTTL.Seconds(),
	}
}

// set up the paths for the roles within vault
func pathConfig(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      "config",
			Fields:       configSchema,
			HelpSynopsis: "Sets the configuration settings for the plugin.",
			HelpDescription: `
This path allows you to set the defaults used in roles.
			`,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.pathUpdateConfig,
				logical.ReadOperation:   backend.pathReadConfig,
			},
		},
	}

	return paths
}

func defaultConfig() *configStorageEntry {
	return &configStorageEntry{
		DefaultTokenTTL:    time.Minute * 15,
		DefaultMaxTokenTTL: time.Hour * 1,
	}
}

func getConfig(ctx context.Context, req *logical.Request) (*configStorageEntry, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return defaultConfig(), err
	}
	if entry == nil {
		return defaultConfig(), nil
	}

	var config configStorageEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return defaultConfig(), err
	}

	return &config, nil
}

func writeConfig(ctx context.Context, req *logical.Request, config *configStorageEntry) error {
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("unable to marshal entry into JSON")
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return err
	}

	return nil
}

func (backend *JwtBackend) pathUpdateConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	if tokenTTL, ok := data.Get("default_token_ttl").(int); ok {
		config.DefaultTokenTTL = time.Second * time.Duration(tokenTTL)
	}

	if tokenTTL, ok := data.Get("default_max_token_ttl").(int); ok {
		config.DefaultMaxTokenTTL = time.Second * time.Duration(tokenTTL)
	}

	if err = writeConfig(ctx, req, config); err != nil {
		return logical.ErrorResponse("err writing config"), err
	}

	return &logical.Response{Data: config.toMap()}, nil
}

func (backend *JwtBackend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req)
	if err != nil {
		return logical.ErrorResponse("err reading existing config"), err
	}

	return &logical.Response{Data: config.toMap()}, nil
}

func getDurationOrDefault(data *framework.FieldData, key string, d time.Duration) time.Duration {
	if t, ok := data.GetOk(key); ok {
		return time.Second * time.Duration(t.(int))
	}
	return d
}
