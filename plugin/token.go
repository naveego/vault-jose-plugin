package josejwt

import (
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
func ValidateJWTToken(serializedToken string, roleEntry RoleStorageEntry, key jose.JSONWebKey) error {

	token, err := jwt.ParseSigned(serializedToken)
	if err != nil {
		return err
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
func CreateJWTToken(createEntry TokenCreateEntry, roleEntry RoleStorageEntry, keyEntry KeyStorageEntry) ([]byte, error) {

	var (
		err error
	)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(keyEntry.PrivateKey.Algorithm), Key: keyEntry.PrivateKey.Key}, (&jose.SignerOptions{}).WithType("JWT"))
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
