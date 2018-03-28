package josejwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/fatih/structs"
	"github.com/google/uuid"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TokenCreateEntry is the exposed structure for creating a token
type TokenCreateEntry struct {
	TTL time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	ID string `json:"id" structs:"id" mapstructure:"id"`

	Claims map[string]interface{} `json:"claims" structs:"claims" mapstructure:"claims"`

	Role string `json:"role" structs:"role" mapstructure:"role"`

	KeyName string `json:"key_name" structs:"key_name" mapstructure:"key_name"`
}

func (t TokenCreateEntry) ToMap() map[string]interface{} {
	return structs.New(t).Map()
}

// ValidateJWTToken will return an error if the token is not valid based on the role and the key.
func ValidateJWTToken(serializedToken string, roleEntry RoleStorageEntry, keySet *KeySetStorageEntry) error {

	token, err := jwt.ParseSigned(serializedToken)
	if err != nil {
		return err
	}

	var kid string
	for _, header := range token.Headers {
		if header.KeyID != "" {
			kid = header.KeyID
			break
		}
	}

	if kid == "" {
		return errors.New("no `kid` header found")
	}

	key, ok := keySet.Keys[kid]
	if !ok {
		return errors.New("`kid` header did not match available keys")
	}

	var validationKey interface{}
	switch key.Key.(type) {
	case []byte:
		validationKey = key
	default:
		validationKey = key.Public()
	}

	claims := jwt.Claims{}
	if err := token.Claims(validationKey, &claims); err != nil {
		return fmt.Errorf("could not parse signed claims: %s", err)
	}

	expected := jwt.Expected{
		Time:   time.Now().UTC(),
		Issuer: roleEntry.Issuer,
	}

	if roleEntry.Audience != "" {
		expected.Audience = []string{roleEntry.Audience}
	}

	err = claims.Validate(expected)

	return err
}

// CreateJWTToken will create a token using the parameters in the token entry, the defaults in the role entry, and signed using the key.
func CreateJWTToken(createEntry TokenCreateEntry, roleEntry RoleStorageEntry, key jose.JSONWebKey) ([]byte, error) {

	var (
		err error
	)

	options := (&jose.SignerOptions{}).WithType("JWT")

	switch key.Key.(type) {
	case []byte:
		// go-jose doesn't set the kid for symmetric keys
		options = options.WithHeader(jose.HeaderKey("kid"), key.KeyID)
	}

	sig, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       &key,
	}, options)

	if err != nil {
		return nil, err
	}

	claims := jwt.Claims{}

	id, _ := uuid.NewUUID()

	claims.ID = id.String()

	if roleEntry.Audience != "" {
		claims.Audience = []string{roleEntry.Audience}
	}
	if roleEntry.Issuer != "" {
		claims.Issuer = roleEntry.Issuer
	}
	if roleEntry.Subject != "" {
		claims.Subject = roleEntry.Subject
	}
	if roleEntry.ExpirationTime {
		utc := time.Now().UTC().Add(createEntry.TTL)
		claims.Expiry = jwt.NewNumericDate(utc)
	}
	if roleEntry.NotBefore {
		claims.NotBefore = jwt.NewNumericDate(time.Now())
	}
	if roleEntry.IssuedAt {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}

	privateClaims := make(map[string]interface{}, len(roleEntry.Claims))

	for claimType, value := range roleEntry.Claims {
		privateClaims[claimType] = value
	}

	if len(createEntry.Claims) > 0 {
		for _, claimType := range roleEntry.AllowedCustomClaims {
			if value, ok := createEntry.Claims[claimType]; ok {
				privateClaims[claimType] = value
			}
		}
	}

	raw, err := jwt.Signed(sig).Claims(claims).Claims(privateClaims).CompactSerialize()
	return []byte(raw), err
}

func (backend *JwtBackend) createToken(createEntry TokenCreateEntry, roleEntry RoleStorageEntry, key jose.JSONWebKey) ([]byte, error) {

	switch roleEntry.Type {
	case "jws":
		return nil, nil
	case "jwt":
		return CreateJWTToken(createEntry, roleEntry, key)
	default:
		// throw an error
		return nil, fmt.Errorf("unsupported token type %s", roleEntry.Type)
	}

}
