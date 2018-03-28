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

var _ = Describe("PathRole", func() {

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

			KeySet:              "test-key",
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

	Describe("create+read roles/:name", func() {

		It("should round trip role", func() {

			Expect(createRole(b, storage, roleEntry.ToMap())).ToNot(HaveLogicalError())

			getReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("roles/%s", roleName),
				Storage:   storage,
			}

			result, err := b.HandleRequest(context.Background(), getReq)
			Expect(result, err).ToNot(HaveLogicalError())

			Expect(result.Data).To(
				And(
					HaveKeyWithValue("key_set", "test-key"),
					HaveKeyWithValue("exp", true),
					HaveKeyWithValue("type", "jwt"),
					HaveKeyWithValue("sub", "test-subject"),
					HaveKeyWithValue("token_ttl", float64(5)),
					HaveKeyWithValue("iat", true),
					HaveKeyWithValue("name", "test-role"),
					HaveKeyWithValue("iss", "test-issuer"),
					HaveKeyWithValue("aud", "test-audience"),
					HaveKeyWithValue("nbf", true),
					HaveKeyWithValue("max_token_ttl", float64(100)),
					HaveKeyWithValue("allowed_custom_claims", BeEquivalentTo([]string{"overridable", "exp"})),
					HaveKeyWithValue("claims", BeEquivalentTo(map[string]interface{}{
						"custom":      "custom-value",
						"overridable": "overridable-value",
					}),
					),
				),
			)
		})

		It("should use configured defaults", func() {

			roleData := roleEntry.ToMap()
			delete(roleData, "token_ttl")
			delete(roleData, "max_token_ttl")

			Expect(createRole(b, storage, roleData)).ToNot(HaveLogicalError())

			result, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("roles/%s", roleName),
				Storage:   storage,
			})
			Expect(result, err).ToNot(HaveLogicalError())

			Expect(result.Data).To(
				And(
					HaveKeyWithValue("token_ttl", (time.Minute*15).Seconds()),
					HaveKeyWithValue("max_token_ttl", (time.Minute*60).Seconds()),
				),
			)
		})

	})

	Describe("create+delete+read roles/:name", func() {

		It("should delete role", func() {

			Expect(createRole(b, storage, roleEntry.ToMap())).ToNot(HaveLogicalError())

			deleteReq := &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      fmt.Sprintf("roles/%s", roleName),
				Storage:   storage,
			}

			Expect(b.HandleRequest(context.Background(), deleteReq)).ToNot(HaveLogicalError())

			getReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("roles/%s", roleName),
				Storage:   storage,
			}

			result, err := b.HandleRequest(context.Background(), getReq)
			Expect(result, err).ToNot(HaveLogicalError())
			Expect(result).To(BeNil())

		})

	})

})
