package josejwt

import (
	"context"
	"log"
	"os"

	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
)

// JwtBackend export type backend for use else where
type JwtBackend struct {
	*framework.Backend
	view logical.Storage
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(ctx, conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend export the function to create backend and configure
func Backend(ctx context.Context, conf *logical.BackendConfig) *JwtBackend {
	backend := &JwtBackend{
		view: conf.StorageView,
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		//		AuthRenew:   backend.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"jwt/validate/*",
				"jwks/*",
				"roles/jwks/*",
			},
			SealWrapStorage: []string{
				"keys/",
			},
		},
		Secrets: []*framework.Secret{
			secretJWT(backend),
		},
		Paths: framework.PathAppend(
			pathJWT(backend),
			pathKeys(backend),
			pathJWKS(backend),
			pathRole(backend),
			pathConfigLease(backend),
			pathConfigURLs(backend),
		),
	}

	return backend
}

// the main app, this will accept the api meta data and tokens from vault
func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}
