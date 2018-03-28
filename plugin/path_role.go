package josejwt

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// basic schema for the creation of the role, this will map the fields coming in from the
// vault request field map
var CreateRoleSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the role to be created.",
	},
	"type": {
		Type:        framework.TypeString,
		Description: "The type of token returned (jwe|jwt|jws).",
	},
	"key_set": {
		Type:        framework.TypeString,
		Description: "The name of the key set to use for signing/encryption.",
	},
	"token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The default TTL of tokens created through this role, as a golang duration string.",
	},
	"max_token_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: "The maximum TTL of tokens created through this role, as a golang duration string.",
	},
	"claims": {
		Type: framework.TypeMap,
		Description: `The structure of the public/private claims to be added to the token
in addition to the standard registered claims configured directly on the role (iss, sub, aud, nbf, iat, exp).`,
	},
	"allowed_custom_claims": {
		Type:        framework.TypeStringSlice,
		Description: "Array of claims which will be accepted as parameters in the issue request and used instead of the values set in the Claims map.",
		Default:     false,
	},

	"iss": {Type: framework.TypeString, Description: "Issuer"},
	"sub": {Type: framework.TypeString, Description: "Subject"},
	"aud": {Type: framework.TypeString, Description: "Audience"},
	"nbf": {Type: framework.TypeBool, Default: true, Description: "Not Before. Automatically added when tokens are issued. To disable, set to false."},
	"iat": {Type: framework.TypeBool, Default: true, Description: "Issued At. Automatically added when tokens are issued. To disable, set to false."},
	"exp": {Type: framework.TypeBool, Default: true, Description: "Expiration Time. Automatically added when tokens are issued. To disable, set to false."},
}

// set up the paths for the roles within vault
func pathRole(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:      fmt.Sprintf("roles/jwks/%s", framework.GenericNameRegex("name")),
			HelpSynopsis: "Returns the JWKS for the keys used by this role.",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The name of the role to get keys for.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: backend.pathReadRoleJWKS,
			},
		},
		&framework.Path{
			Pattern:      fmt.Sprintf("roles/%s", framework.GenericNameRegex("name")),
			Fields:       CreateRoleSchema,
			HelpSynopsis: "CRUD operations on roles. Roles define how tokens can be generated from keys.",
			HelpDescription: `When a role name is passed to the jwt/issue endpoint, a token will be created using the 
claims and TTL settings of that role.`,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.createRole,
				logical.UpdateOperation: backend.createRole,
				logical.ReadOperation:   backend.readRole,
				logical.DeleteOperation: backend.removeRole,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) pathReadRoleJWKS(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

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

// remove the specified role from the storage
func (backend *JwtBackend) removeRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Unable to remove, missing role name"), nil
	}

	// get the role to make sure it exists and to get the role id
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// remove the role
	if err := backend.deleteRoleEntry(ctx, req.Storage, roleName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Unable to remove role %s", roleName)), err
	}

	return &logical.Response{}, nil
}

// read the current role from the inputs and return it if it exists
func (backend *JwtBackend) readRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	if role == nil {
		return nil, nil
	}

	return &logical.Response{Data: role.ToMap()}, nil
}

// create the role within plugin, this will provide the access for applications
// to be able to create tokens down the line
func (backend *JwtBackend) createRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, _ := getConfig(ctx, req)

	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("Role name not supplied"), nil
	}

	role, err := backend.getRoleEntry(ctx, req.Storage, roleName)
	if err != nil {
		return logical.ErrorResponse("Error reading role"), err
	}

	if role == nil {
		role = new(RoleStorageEntry)

		// set the role ID
		roleID, _ := uuid.NewUUID()
		role.RoleID = roleID.String()

	}

	if name, ok := data.GetOk("name"); !ok {
		return logical.ErrorResponse("name is required"), nil
	} else {
		if role.Name, ok = name.(string); !ok {
			return logical.ErrorResponse("name must be a string"), nil
		}
	}

	if tokenType, ok := data.GetOk("type"); !ok {
		return logical.ErrorResponse("type is required"), nil
	} else {
		if role.Type, ok = tokenType.(string); !ok {
			return logical.ErrorResponse("type must be a string"), nil
		}

		if role.Type != "jwt" && role.Type != "jws" && role.Type != "jwe" {
			return logical.ErrorResponse("type must be one of jwt|jws|jwe"), nil
		}
	}

	keySet, ok := data.GetOk("key_set")
	if !ok {
		return logical.ErrorResponse("key_set is required"), nil
	}
	role.KeySet = keySet.(string)

	role.TokenTTL = getDurationOrDefault(data, "token_ttl", config.Lease)
	role.MaxTokenTTL = getDurationOrDefault(data, "max_token_ttl", config.LeaseMax)

	if claims, ok := data.GetOk("claims"); ok {
		if role.Claims, ok = claims.(map[string]interface{}); !ok {
			return logical.ErrorResponse("claims must be a map"), nil
		}
	} else {
		role.Claims = make(map[string]interface{})
	}

	if allowedCustomClaims, ok := data.GetOk("allowed_custom_claims"); ok {
		if role.AllowedCustomClaims, ok = allowedCustomClaims.([]string); !ok {
			return logical.ErrorResponse("allowed_custom_claims must be a string array"), nil
		}
	} else {
		role.AllowedCustomClaims = []string{}
	}

	role.Issuer, _ = data.Get("iss").(string)
	role.Subject, _ = data.Get("sub").(string)
	role.Audience, _ = data.Get("aud").(string)

	role.ExpirationTime = getBoolOrDefault(data, "exp", true)
	role.IssuedAt = getBoolOrDefault(data, "iat", true)
	role.NotBefore = getBoolOrDefault(data, "nbf", true)

	if err := backend.setRoleEntry(ctx, req.Storage, *role); err != nil {
		return logical.ErrorResponse("Error saving role"), err
	}

	roleDetails := map[string]interface{}{
		"role_id": role.RoleID,
	}
	return &logical.Response{Data: roleDetails}, nil
}

func getBoolOrDefault(data *framework.FieldData, key string, d bool) bool {

	if vr, ok := data.GetOk(key); ok {
		if v, ok := vr.(bool); ok {
			return v
		}
	}
	return d
}
