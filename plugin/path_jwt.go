package josejwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// basic schema for the creation of the token,
// this will map the fields coming in from the vault request field map
var createTokenSchema = map[string]*framework.FieldSchema{

	"role": {
		Type:        framework.TypeString,
		Description: "The name of the role to use to create the token",
	},
	"claims": {
		Type:        framework.TypeMap,
		Description: "The claims to add to the token.",
	},
	"token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The duration in seconds after which the token will expire",
	},
}

// basic schema for the validation of the token,
// this will map the fields coming in from the vault request field map
var validateTokenSchema = map[string]*framework.FieldSchema{
	"role": {
		Type:        framework.TypeString,
		Description: "The role associated with this token",
	},
	"token": {
		Type:        framework.TypeString,
		Description: "The Token to validate",
	},
}

func pathJWT(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern: fmt.Sprintf("jwt/issue/%s", framework.GenericNameRegex("role")),
			Fields:  createTokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.pathJwtIssue,
			},
		},
		&framework.Path{
			Pattern: fmt.Sprintf("jwt/validate/%s", framework.GenericNameRegex("role")),
			Fields:  validateTokenSchema,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: backend.pathJwtValidate,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) pathJwtIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	tokenEntry := TokenCreateEntry{
		Role:   data.Get("role").(string),
		Claims: data.Get("claims").(map[string]interface{}),
	}

	if tokenTTL, ok := data.Get("token_ttl").(int); ok {
		tokenEntry.TTL = time.Second * time.Duration(tokenTTL)
	}

	// get the role by name
	roleEntry, err := backend.getRoleEntry(ctx, req.Storage, tokenEntry.Role)
	if roleEntry == nil || err != nil {
		err = fmt.Errorf("role %q not recognised", tokenEntry.Role)
		return logical.ErrorResponse(err.Error()), err
	}

	keyEntry, err := backend.getKeyEntry(ctx, req.Storage, roleEntry.Key)
	if keyEntry == nil || err != nil {
		err = fmt.Errorf(fmt.Sprintf("key %q for role %q not recognized", roleEntry.Key, tokenEntry.Role))
		return logical.ErrorResponse(err.Error()), err
	}

	if tokenEntry.TTL == 0 {
		// no TTL so use the default from the role
		tokenEntry.TTL = roleEntry.TokenTTL
	}

	if tokenEntry.TTL > roleEntry.MaxTokenTTL {
		// requested TTL exceeds max, so clip it
		tokenEntry.TTL = roleEntry.MaxTokenTTL
	}

	token, err := backend.createToken(tokenEntry, *roleEntry, *keyEntry)

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error creating token, %#v", err)), err
	}

	response := backend.Secret(SecretJWTType).Response(map[string]interface{}{"token": string(token)}, tokenEntry.ToMap())
	response.Secret.TTL = tokenEntry.TTL
	response.Secret.Renewable = roleEntry.ExpirationTime

	return response, nil
}

// Provides basic token validation for a provided jwt token
func (backend *JwtBackend) pathJwtValidate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	var (
		roleName string
		token    string
		ok       bool
	)

	roleName, ok = data.Get("role").(string)
	if !ok {
		return logical.ErrorResponse("role was missing"), nil
	}

	// get the role by name
	roleEntry, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if roleEntry == nil || err != nil {
		err = fmt.Errorf("Role name %q not recognised", roleName)
		return logical.ErrorResponse(err.Error()), err
	}

	keyEntry, err := backend.getKeyEntry(ctx, req.Storage, roleEntry.Key)
	if keyEntry == nil || err != nil {
		err = fmt.Errorf(fmt.Sprintf("Key name %q for role name %q not recognized", roleEntry.Key, roleName))
		return logical.ErrorResponse(err.Error()), err
	}

	token, ok = data.Get("token").(string)
	if !ok {
		return logical.ErrorResponse("token was missing"), nil
	}

	if token == "" {
		err = errors.New("token was missing")
		return logical.ErrorResponse(err.Error()), err
	}

	err = ValidateJWTToken(token, *roleEntry, *keyEntry)

	if err == nil {
		return &logical.Response{Data: map[string]interface{}{
			"is_valid": true,
		}}, nil
	}

	return &logical.Response{Data: map[string]interface{}{
		"is_valid": false,
		"error":    err.Error(),
	}}, nil

}
