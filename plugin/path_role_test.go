package josejwt_test

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	//. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PathRole", func() {

	var (
		b        logical.Backend
		storage  logical.Storage
		roleData map[string]interface{}
		roleName string
	)

	BeforeEach(func() {
		roleName = "test-role"
		b, storage = getTestBackend()
		roleData = map[string]interface{}{
			"name": roleName,
			"allowed_custom_claims": []string{"overridable",
				"exp"},
			"iss":           "test-issuer",
			"aud":           "test-audience",
			"nbf":           true,
			"key":           "test-key",
			"max_token_ttl": 100,
			"sub":           "test-subject",
			"token_ttl":     5,
			"exp":           true,
			"type":          "jwt",
			"claims": map[string]interface{}{
				customClaimTye:       customClaimValue,
				overridableClaimType: overridableClaimInitialValue,
			},
			"iat": true,
		}
	})

	Describe("PUT+GET roles/:name", func() {

		It("should round trip role", func() {

			Expect(createRole(b, storage, roleData)).ToNot(HaveLogicalError())

			getReq := &logical.Request{
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("roles/%s", roleName),
				Storage:   storage,
			}

			result, err := b.HandleRequest(context.Background(), getReq)
			Expect(result, err).ToNot(HaveLogicalError())

			Expect(result.Data).To(HaveKeyWithValue("key", "test-key"))
			Expect(result.Data).To(HaveKeyWithValue("exp", true))
			Expect(result.Data).To(HaveKeyWithValue("type", "jwt"))
			Expect(result.Data).To(HaveKeyWithValue("sub", "test-subject"))
			Expect(result.Data).To(HaveKeyWithValue("token_ttl", float64(5)))
			Expect(result.Data).To(HaveKeyWithValue("iat", true))
			Expect(result.Data).To(HaveKeyWithValue("name", "test-role"))
			Expect(result.Data).To(HaveKeyWithValue("iss", "test-issuer"))
			Expect(result.Data).To(HaveKeyWithValue("aud", "test-audience"))
			Expect(result.Data).To(HaveKeyWithValue("nbf", true))
			Expect(result.Data).To(HaveKeyWithValue("max_token_ttl", float64(100)))
			Expect(result.Data).To(HaveKeyWithValue("allowed_custom_claims", BeEquivalentTo([]string{"overridable", "exp"})))
			Expect(result.Data).To(HaveKeyWithValue("claims", BeEquivalentTo(map[string]interface{}{
				"custom":      "custom-value",
				"overridable": "overridable-value",
			})))

		})

	})

	Describe("PUT+DELETE roles/:name", func() {

		It("should delete role", func() {

			Expect(createRole(b, storage, roleData)).ToNot(HaveLogicalError())

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
