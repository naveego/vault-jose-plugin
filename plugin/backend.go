package josejwt

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/hashicorp/vault/helper/locksutil"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/logical/plugin"
)

// JwtBackend export type backend for use else where
type JwtBackend struct {
	*framework.Backend
	view logical.Storage

	// The salt value to be used by the information to be accessed only
	// by this backend.
	salt      *salt.Salt
	saltMutex sync.RWMutex

	// Locks for guarding service clients
	clientMutex sync.RWMutex

	roleLocks   []*locksutil.LockEntry
	secretLocks []*locksutil.LockEntry
	keyLocks    []*locksutil.LockEntry
	claimLocks  []*locksutil.LockEntry
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(ctx, conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Salt create the Salt for encrypting the keys
func (backend *JwtBackend) Salt(ctx context.Context) (*salt.Salt, error) {
	backend.saltMutex.RLock()
	if backend.salt != nil {
		defer backend.saltMutex.RUnlock()
		return backend.salt, nil
	}
	backend.saltMutex.RUnlock()
	backend.saltMutex.Lock()
	defer backend.saltMutex.Unlock()
	if backend.salt != nil {
		return backend.salt, nil
	}
	salt, err := salt.NewSalt(ctx, backend.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	backend.salt = salt
	return salt, nil
}

// reset the salt
func (backend *JwtBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case salt.DefaultLocation:
		backend.saltMutex.Lock()
		defer backend.saltMutex.Unlock()
		backend.salt = nil
	}
}

// func (backend *JwtBackend) pathAuthRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
// 	// TODO
// 	return nil, nil
// }

// Backend export the function to create backend and configure
func Backend(ctx context.Context, conf *logical.BackendConfig) *JwtBackend {
	backend := &JwtBackend{
		view:        conf.StorageView,
		roleLocks:   locksutil.CreateLocks(),
		secretLocks: locksutil.CreateLocks(),
		keyLocks:    locksutil.CreateLocks(),
		claimLocks:  locksutil.CreateLocks(),
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		//		AuthRenew:   backend.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"token/validate"},
		},
		Invalidate: backend.invalidate,
		Paths: framework.PathAppend(
			pathToken(backend),
			pathKeys(backend),
			pathRole(backend),
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
