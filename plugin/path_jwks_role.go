package josejwt

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// set up the paths for the roles within vault
func pathJWKS(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      fmt.Sprintf("jwks/%s", framework.GenericNameRegex("name")),
			HelpSynopsis: "Returns the JWKS for the keys used by this role.",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The name of the role to get keys for.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: backend.readRoleJWKS,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) readRoleJWKS(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("error reading role"), err
	}

	if role == nil {
		return nil, nil
	}

	keySetEntry, err := backend.getKeySetEntry(ctx, req.Storage, role.KeySet)
	if keySetEntry == nil || err != nil {
		err = fmt.Errorf(fmt.Sprintf("key set %q for role name %q not recognized", role.KeySet, roleName))
		return logical.ErrorResponse(err.Error()), err
	}

	var keys []interface{}

	for kid := range keySetEntry.Keys {
		key := keySetEntry.GetPublicKey(kid)
		if key != nil {
			keys = append(keys, key)
		}
	}

	return &logical.Response{Data: map[string]interface{}{
		"keys": keys,
	}}, nil
}
