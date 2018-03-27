package josejwt_test

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PathJWKS", func() {

	var (
		b        logical.Backend
		storage  logical.Storage
		roleName string
	)

	BeforeEach(func() {
		roleName = "test-role"
		b, storage = getTestBackend()
	})

	Describe("read roles/:name/jwks", func() {

		It("should return jwks", func() {

			Expect(createKey(b, storage, map[string]interface{}{
				"name": keyName,
				"alg":  "RS256",
				"use":  "sig",
			})).NotTo(HaveLogicalError())

			Expect(createRole(b, storage, RoleStorageEntry{
				Name:   roleName,
				Type:   "jwt",
				KeySet: "test-key",
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
