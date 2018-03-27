package josejwt

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const SecretJWTType = "jwt"

func secretJWT(b *JwtBackend) *framework.Secret {
	return &framework.Secret{
		Type: SecretJWTType,
		Fields: map[string]*framework.FieldSchema{
			"token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "JWT token in compact serialization format.",
			},
		},

		//Renew:  b.secretJWTRenew,
		Revoke: b.secretJWTRevoke,
	}
}

func (b *JwtBackend) secretJWTRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	f := framework.LeaseExtend(0, 0, b.System())
	return f(ctx, req, d)
}

func (b *JwtBackend) secretJWTRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	return nil, nil
}
