package josejwt

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"

	"gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/vault/sdk/logical"
)

var keySetSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The intended endpoints of the token to validate the claim",
	},
	"active_kid": {
		Type:        framework.TypeString,
		Description: "The `kid` of the key which should be used to sign things.",
	},
}

var addKeySchema = map[string]*framework.FieldSchema{
	"key_set_name": {
		Type:        framework.TypeString,
		Description: "The name of the key set to add the key to.",
	},
	"kid": {
		Type:        framework.TypeString,
		Description: "The key ID.",
	},
	"jwk": {
		Type:        framework.TypeString,
		Description: "The JWK for the key, as a string.",
	},
	"pem": {
		Type:        framework.TypeString,
		Description: "The PEM-encoded data for the key. If you use this parameter you must also pass the `alg` parameter.",
	},
	"use": {
		Type:        framework.TypeString,
		Description: "The usage of this key, 'enc' or 'sig'. Required if 'jwk' is not set.",
	},
	"alg": {
		Type:        framework.TypeString,
		Description: "The algorithm (from JWA). Required if 'jwk' is not set.",
	},
	"rsa_bits": {
		Type:        framework.TypeInt,
		Default:     2048,
		Description: "Optional; the size of the key if an RSA key is generated.",
	},
	"symmetric_bits": {
		Type:        framework.TypeInt,
		Default:     256,
		Description: "Optional; the size of the key if a symmetric key is generated.",
	},
	"active": {
		Type:    framework.TypeBool,
		Default: false,
		Description: `If this is true, the new key will be made the active key of the key set. 
If the key set is being automatically created, this will default to true. Otherwise, it defaults to false.`,
	},
}

var keySetJWKSSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the key set.",
	},
}

const keySetHelpDescription = `
This endpoint allows you to manage key sets. 

You can create or delete a key set, or set the active key.

You can add keys to a key set, either by providing an existing key or
by asking the key set to generate one.

If you add a key to a keyset that does not exist, the key set will be created 
and set as the active key. This makes it easy to create key sets that only
contain one key: 

	vault write jose/jwks/<key_set_name>/<kid> alg=... use=...

`

func pathJWKS(backend *JwtBackend) []*framework.Path {
	paths := []*framework.Path{
		&framework.Path{
			Pattern:         "jwks/?$",
			HelpSynopsis:    "Key sets.",
			HelpDescription: keySetHelpDescription,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: backend.pathListKeySets,
			},
		},
		&framework.Path{
			Pattern:         fmt.Sprintf("jwks/%s/?$", framework.GenericNameRegex("name")),
			Fields:          keySetSchema,
			HelpSynopsis:    "This path handles CRUD operations on key sets.",
			HelpDescription: keySetHelpDescription,
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				keyName := data.Get("name").(string)
				key, err := backend.getKeySetEntry(ctx, req.Storage, keyName)
				return key != nil, err
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.pathCreateUpdateKeySet,
				logical.UpdateOperation: backend.pathCreateUpdateKeySet,
				logical.DeleteOperation: backend.pathDeleteKeySet,
				logical.ReadOperation:   backend.pathReadKeySet,
				logical.ListOperation:   backend.pathListKeysInKeySet,
			},
		},
		&framework.Path{
			Pattern:      fmt.Sprintf("jwks/%s/public", framework.GenericNameRegex("name")),
			Fields:       keySetJWKSSchema,
			HelpSynopsis: "This public JWKS endpoint.",
			HelpDescription: `
This endpoint returns the JWKS formatted representation of the key set.

You do not need to be authenticated to request this resource.
			`,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: backend.pathReadKeySetPublic,
			},
		},
		&framework.Path{
			Pattern:      fmt.Sprintf("jwks/%s/%s", framework.GenericNameRegex("key_set_name"), framework.GenericNameRegex("kid")),
			Fields:       addKeySchema,
			HelpSynopsis: "This path handles adding, removing, and generating keys in key sets.",
			HelpDescription: `
Write to this endpoint to add a key to a key set. 

You can have the plugin generate a key for you by setting the 'alg' and 'use' parameters and not setting 'jwk', 'pem', or 'der'.

If you already have a key, you can provide it in JWK or PEM format using the 'jwk' or 'pem' parameters.

If you use the PEM format you must set 'alg' and 'use' as well.
`,
			ExistenceCheck: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
				keyName := data.Get("key_set_name").(string)
				keySet, err := backend.getKeySetEntry(ctx, req.Storage, keyName)
				if err != nil {
					return false, err
				}
				if keySet == nil {
					return false, err
				}

				kid := data.Get("kid").(string)

				_, ok := keySet.Keys[kid]

				return ok, nil
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: backend.pathAddKeyToKeySet,
				logical.UpdateOperation: backend.pathAddKeyToKeySet,
				logical.ReadOperation:   backend.pathReadKeyFromKeySet,
				logical.DeleteOperation: backend.pathDeleteKeyFromKeySet,
			},
		},
	}

	return paths
}

func (backend *JwtBackend) pathCreateUpdateKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	key, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("error reading key"), err
	}

	if key == nil {
		key = &KeySetStorageEntry{
			Name: name,
			Keys: make(map[string]jose.JSONWebKey),
		}
	}

	if activeKID, ok := data.GetOk("active_kid"); ok {
		if err = key.SetActiveKID(activeKID.(string)); err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	if err := backend.setKeySetEntry(ctx, req.Storage, key); err != nil {
		return logical.ErrorResponse("error saving key set"), err
	}

	return &logical.Response{Data: key.ToMap()}, nil
}

func (backend *JwtBackend) pathReadKeySetPublic(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	keySet, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("error reading key set"), err
	}

	if keySet == nil {
		return nil, nil
	}

	var keys []interface{}

	for kid := range keySet.Keys {
		key := keySet.GetPublicKey(kid)
		if key.Valid() && key.IsPublic() {
			keys = append(keys, key)
		}
	}

	return &logical.Response{Data: map[string]interface{}{
		"keys": keys,
	}}, nil
}

func (backend *JwtBackend) pathReadKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	key, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("error reading key set"), err
	}

	if key == nil {
		return nil, nil
	}

	return &logical.Response{Data: key.ToMap()}, nil
}

func (backend *JwtBackend) pathDeleteKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keyName := data.Get("name").(string)

	if err := backend.deleteKeySetEntry(ctx, req.Storage, keyName); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("error deleting key: %s", err)), err
	}

	return &logical.Response{Data: map[string]interface{}{
		"result": fmt.Sprintf("key with name %q was deleted (if it existed)", keyName),
	}}, nil
}

func (backend *JwtBackend) pathListKeySets(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	list, err := req.Storage.List(ctx, "keyset/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(list), nil
}

func (backend *JwtBackend) pathListKeysInKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	name := data.Get("name").(string)
	key, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("error reading key set"), err
	}

	if key == nil {
		return nil, nil
	}

	var list []string

	for kid := range key.Keys {
		list = append(list, kid)
	}

	return logical.ListResponse(list), nil
}

func (backend *JwtBackend) pathAddKeyToKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	kid := data.Get("kid").(string)
	if kid == "" {
		return logical.ErrorResponse("missing key id"), nil
	}

	makeActive := data.Get("active").(bool)

	name := data.Get("key_set_name").(string)
	keySet, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("invalid key set"), err
	}

	if keySet == nil {
		makeActive = true
		keySet = &KeySetStorageEntry{
			Name: name,
			Keys: make(map[string]jose.JSONWebKey),
		}
	}

	if keySet.Exists(kid) {
		return &logical.Response{
			Data: keySet.PublicKeyAsMap(kid),
			Warnings: []string{
				fmt.Sprintf("A key with kid=%s already exists. Existing keys cannot be modified. If you really need to modify a key, delete it and add a new key with the same ID. This will break all tokens using that key.", kid),
			},
		}, nil

	}

	jsonWebKey := new(jose.JSONWebKey)
	alg := data.Get("alg").(string)
	use := data.Get("use").(string)

	if jwtRaw, ok := data.GetOk("jwt"); ok {

		if err := jsonWebKey.UnmarshalJSON([]byte(jwtRaw.(string))); err != nil {
			return logical.ErrorResponse(fmt.Sprintf("invalid jwt: %s", err)), nil
		}

		jsonWebKey.KeyID = kid

	} else {

		if alg == "" {
			return logical.ErrorResponse("if `jwk` is not provided you must provide `alg`"), nil
		}
		if use == "" {
			return logical.ErrorResponse("if `jwk` is not provided you must provide `use`"), nil
		}

		if pemRaw, ok := data.GetOk("pem"); ok {

			privateKey, err := LoadPrivateKey([]byte(pemRaw.(string)))

			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("could not decode PEM: %s", err)), nil
			}

			jsonWebKey.Key = privateKey

			jsonWebKey.Algorithm = alg
			jsonWebKey.Use = use
			jsonWebKey.KeyID = kid

		} else {
			var (
				rsaBits       int
				symmetricBits int
			)

			rsaBits = data.Get("rsa_bits").(int)
			symmetricBits = data.Get("symmetric_bits").(int)

			jsonWebKey, err = GenerateKey(kid, alg, use, rsaBits, symmetricBits)
			if err != nil {
				return logical.ErrorResponse(fmt.Sprintf("invalid key parameters: %s", err)), nil
			}
		}
	}

	if err := keySet.AddKey(*jsonWebKey); err != nil {
		return logical.ErrorResponse(fmt.Sprintf("invalid request: %s", err)), nil
	}

	if makeActive || keySet.ActiveKID == "" {
		if err := keySet.SetActiveKID(kid); err != nil {
			return nil, fmt.Errorf("the key we just added (with `kid` %q) is missing: %s", kid, err)
		}
	}

	if err := backend.setKeySetEntry(ctx, req.Storage, keySet); err != nil {
		return logical.ErrorResponse("error saving key set"), err
	}

	return &logical.Response{
		Data: keySet.PublicKeyAsMap(kid),
	}, nil
}

func (backend *JwtBackend) pathDeleteKeyFromKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	name := data.Get("key_set_name").(string)
	key, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("invalid key set"), err
	}

	if key == nil {
		return logical.ErrorResponse("no such key set"), nil
	}

	kid := data.Get("kid").(string)

	key.RemoveKey(kid)

	if err := backend.setKeySetEntry(ctx, req.Storage, key); err != nil {
		return logical.ErrorResponse("error saving key set"), err
	}

	return &logical.Response{Data: key.ToMap()}, nil

}

func (backend *JwtBackend) pathReadKeyFromKeySet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	name := data.Get("key_set_name").(string)
	keySet, err := backend.getKeySetEntry(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("invalid key set"), err
	}

	if keySet == nil {
		return logical.ErrorResponse("no such key set"), nil
	}

	kid := data.Get("kid").(string)

	key := keySet.GetPublicKey(kid)

	if !key.Valid() {
		if _, ok := keySet.Keys[kid]; ok {
			return logical.ErrorResponse("key is symmetric"), nil
		}
		return logical.ErrorResponse("no such key"), nil
	}

	keyBytes, err := json.Marshal(key)
	if err != nil {
		return logical.ErrorResponse("error serializing public key"), err
	}

	return &logical.Response{Data: map[string]interface{}{
		"jwk": keyBytes,
	}}, nil
}
