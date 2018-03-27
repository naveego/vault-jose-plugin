package josejwt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
)

// RoleStorageEntry structure that represents the role as it is stored within vault
type RoleStorageEntry struct {
	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	// The provided name for the role.
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// The type of token to be created for the role, jwe|jwt|jws.
	Type string `json:"type" structs:"type" mapstructure:"type"`

	// The name of the key set this role will use to sign/encrypt tokens.
	KeySet string `json:"key_set" structs:"key_set" mapstructure:"key_set"`

	// The default TTL (in seconds) for tokens created through this role.
	TokenTTL time.Duration `json:"token_ttl" structs:"token_ttl" mapstructure:"token_ttl"`

	// The maximum TTL (in seconds) for tokens created through this role (this limit is applied to the requested TTL at issuance.)
	MaxTokenTTL time.Duration `json:"max_token_ttl" structs:"max_token_ttl" mapstructure:"max_token_ttl"`

	// The claims that will be set on a JWT token issued through this role.
	Claims map[string]interface{} `json:"claims" structs:"claims" mapstructure:"claims"`

	// Array of claims which will be accepted as parameters in the issue request and used instead of the values set in the Claims map.
	AllowedCustomClaims []string `json:"allowed_custom_claims" structs:"allowed_custom_claims" mapstructure:"allowed_custom_claims"`

	// Claims:
	// String-valued claims
	Issuer   string `json:"iss" structs:"iss" mapstructure:"iss"`
	Subject  string `json:"sub" structs:"sub" mapstructure:"sub"`
	Audience string `json:"aud" structs:"aud" mapstructure:"aud"`

	ExpirationTime bool `json:"exp" structs:"exp" mapstructure:"exp"`
	NotBefore      bool `json:"nbf" structs:"nbf" mapstructure:"nbf"`
	IssuedAt       bool `json:"iat" structs:"iat" mapstructure:"iat"`
}

func (r RoleStorageEntry) ToMap() map[string]interface{} {
	roleDetails := structs.New(r).Map()
	delete(roleDetails, "role_id")
	roleDetails["token_ttl"] = r.TokenTTL.Seconds()
	roleDetails["max_token_ttl"] = r.MaxTokenTTL.Seconds()
	return roleDetails
}

// roleSave will persist the role in the data store
func (backend *JwtBackend) setRoleEntry(ctx context.Context, storage logical.Storage, role RoleStorageEntry) error {
	if role.Name == "" {
		return fmt.Errorf("Unable to save, invalid name in role")
	}

	roleName := strings.ToLower(role.Name)

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)

	if err != nil {
		return fmt.Errorf("Error converting entry to JSON: %#v", err)
	}

	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("Error saving role: %#v", err)
	}

	return nil
}

// deleteRoleEntry this will remove the role with specified name
func (backend *JwtBackend) deleteRoleEntry(ctx context.Context, storage logical.Storage, roleName string) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}
	roleName = strings.ToLower(roleName)

	return storage.Delete(ctx, fmt.Sprintf("role/%s", roleName))
}

// getRoleEntry grabs the read lock and fetches the options of an role from the storage
func (backend *JwtBackend) getRoleEntry(ctx context.Context, storage logical.Storage, roleName string) (*RoleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role name")
	}
	roleName = strings.ToLower(roleName)

	var result RoleStorageEntry
	if entry, err := storage.Get(ctx, fmt.Sprintf("role/%s", roleName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("could not decode stored role: %s", err)
	}

	return &result, nil
}
