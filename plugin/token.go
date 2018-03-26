package josejwt

import (
	"fmt"
	"time"

	"github.com/SermoDigital/jose/crypto"

	"github.com/SermoDigital/jose/jws"
	"github.com/google/uuid"
)

// TokenCreateEntry is the exposed structure for creating a token
type TokenCreateEntry struct {
	TTL time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	ID string `json:"id" structs:"id" mapstructure:"id"`

	Claims map[string]interface{} `json:"claims" structs:"claims" mapstructure:"claims"`

	RoleName string `json:"role_name" structs:"role_name" mapstructure:"role_name"`

	RoleID string `json:"role_id" structs:"role_id" mapstructure:"role_id"`

	KeyName string `json:"key_name" structs:"key_name" mapstructure:"key_name"`
}

// ValidateJWTToken will return an error if the token is not valid based on the role and the key.
func ValidateJWTToken(serializedToken string, roleEntry RoleStorageEntry, keyEntry KeyStorageEntry) error {

	token, err := jws.ParseJWT([]byte(serializedToken))
	if err != nil {
		return err
	}

	var key interface{}

	signingType := keyEntry.Algorithm[:2]
	switch signingType {
	case "HS":
		key = []byte(keyEntry.PrivateKey)
	case "RS":
		key, err = crypto.ParseRSAPublicKeyFromPEM([]byte(keyEntry.PublicKey))
		if err != nil {
			return fmt.Errorf("key %q is invalid", keyEntry.Name)
		}
	case "EC":
		key, err = crypto.ParseECPublicKeyFromPEM([]byte(keyEntry.PublicKey))
		if err != nil {
			return fmt.Errorf("key %q is invalid", keyEntry.Name)
		}
	}

	signingMethod := jws.GetSigningMethod(keyEntry.Algorithm)

	err = token.Validate(key, signingMethod)

	return err
}

// CreateJWTToken will create a token using the parameters in the token entry, the defaults in the role entry, and signed using the key.
func CreateJWTToken(createEntry TokenCreateEntry, roleEntry RoleStorageEntry, keyEntry KeyStorageEntry) ([]byte, error) {

	var (
		key interface{}
		err error
	)

	if createEntry.TTL == 0 {
		// no TTL so use the default from the role
		createEntry.TTL = roleEntry.TokenTTL
	}

	if createEntry.TTL > roleEntry.MaxTokenTTL {
		// requested TTL exceeds max, so clip it
		createEntry.TTL = roleEntry.MaxTokenTTL
	}

	claims := jws.Claims{}

	id, _ := uuid.NewUUID()

	claims.SetJWTID(id.String())

	if roleEntry.Audience != "" {
		claims.SetAudience(roleEntry.Audience)
	}
	if roleEntry.Issuer != "" {
		claims.SetIssuer(roleEntry.Issuer)
	}
	if roleEntry.Subject != "" {
		claims.SetSubject(roleEntry.Subject)
	}
	if roleEntry.ExpirationTime {
		utc := time.Now().UTC().Add(createEntry.TTL)
		claims.SetExpiration(utc)
	}
	if roleEntry.NotBefore {
		claims.SetNotBefore(time.Now().UTC())
	}
	if roleEntry.IssuedAt {
		claims.SetIssuedAt(time.Now().UTC())
	}

	for claimType, value := range roleEntry.Claims {
		claims[claimType] = value
	}

	if len(createEntry.Claims) > 0 {
		for _, claimType := range roleEntry.AllowedCustomClaims {
			if value, ok := createEntry.Claims[claimType]; ok {
				claims.Set(claimType, value)
			}
		}
	}

	signingType := keyEntry.Algorithm[:2]
	switch signingType {
	case "HS":
		key = []byte(keyEntry.PrivateKey)
	case "RS":
		key, err = crypto.ParseRSAPrivateKeyFromPEM([]byte(keyEntry.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("key %q is invalid", keyEntry.Name)
		}
	case "EC":
		key, err = crypto.ParseECPrivateKeyFromPEM([]byte(keyEntry.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("key %q is invalid", keyEntry.Name)
		}
	}

	signingMethod := jws.GetSigningMethod(keyEntry.Algorithm)

	token := jws.NewJWT(claims, signingMethod)

	serializedToken, err := token.Serialize(key)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %s", err)
	}

	return serializedToken[:], nil
}

func (backend *JwtBackend) createToken(createEntry TokenCreateEntry, roleEntry RoleStorageEntry, keyEntry KeyStorageEntry) ([]byte, error) {

	switch roleEntry.Type {
	case "jws":
		return nil, nil
	case "jwt":
		return CreateJWTToken(createEntry, roleEntry, keyEntry)
	default:
		// throw an error
		return nil, fmt.Errorf("unsupported token type %s", roleEntry.Type)
	}

}
