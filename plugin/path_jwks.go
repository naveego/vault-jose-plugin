package josejwt

import (
	"context"
	"fmt"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"

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

	key, err := backend.getKeyEntry(ctx, req.Storage, role.Key)
	if err != nil {
		return logical.ErrorResponse("error reading key"), err
	}
	if key == nil {
		return nil, nil
	}

	if key.PublicKey == nil || !key.PublicKey.Valid() {
		return nil, nil
	}

	response := &logical.Response{
		Data: map[string]interface{}{},
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			*key.PublicKey,
		},
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("error creating jwks JSON: %s", err)
	}

	if err := json.Unmarshal(jwksBytes, &response.Data); err != nil {
		return nil, fmt.Errorf("error creating jwks data: %s", err)
	}

	return response, nil
}
