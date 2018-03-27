package josejwt_test

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
	. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PathJWKS", func() {

	var (
		b         logical.Backend
		storage   logical.Storage
		roleEntry RoleStorageEntry
		roleName  string
	)

	BeforeEach(func() {
		roleName = "test-role"
		b, storage = getTestBackend()
		roleEntry = RoleStorageEntry{
			Name: roleName,
			Type: "jwt",

			Key:                 "test-key",
			MaxTokenTTL:         100 * time.Second,
			TokenTTL:            5 * time.Second,
			Issuer:              "test-issuer",
			Audience:            "test-audience",
			Subject:             "test-subject",
			NotBefore:           true,
			ExpirationTime:      true,
			IssuedAt:            true,
			AllowedCustomClaims: []string{"overridable", "exp"},
			Claims: map[string]interface{}{
				customClaimTye:       customClaimValue,
				overridableClaimType: overridableClaimInitialValue,
			},
		}
	})

	Describe("read roles/:name/jwks", func() {

		It("should return jwks", func() {

			Expect(createKey(b, storage, map[string]interface{}{
				"name": keyName,
				"alg":  "RS256",
				"use":  "sig",
			})).NotTo(HaveLogicalError())

			Expect(createRole(b, storage, RoleStorageEntry{
				Name: roleName,
				Type: "jwt",
				Key:  "test-key",
			}.ToMap())).ToNot(HaveLogicalError())

			result, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("jwks/%s", roleName),
				Storage:   storage,
			})
			Expect(result, err).ToNot(HaveLogicalError())
			Expect(result.Data).To(And(
				HaveKeyWithValue("keys", HaveLen(1)),
			))

		})

	})
})
