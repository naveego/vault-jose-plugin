package josejwt_test

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jose "gopkg.in/square/go-jose.v2"
	//. "github.com/naveego/vault-jose-plugin/plugin"
)

const keyName = "test-key"

var _ = Describe("PathKeys", func() {

	var (
		b       logical.Backend
		storage logical.Storage
	)

	BeforeEach(func() {
		b, storage = getTestBackend()
	})

	Describe("create/read keys/:name", func() {

		It("should round trip symmetric key", func() {
			entry := map[string]interface{}{
				"name": keyName,
				"jwk":  jose.JSONWebKey{Key: []byte("test-key"), Algorithm: string(jose.HS256)},
			}
			Expect(createKey(b, storage, entry)).NotTo(HaveLogicalError())

			req := &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("keys/%s", keyName),
			}

			resp, err := b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("public_key", BeNil()))
		})

		It("should round trip asymmetric key", func() {
			entry := map[string]interface{}{
				"name": keyName,
				"alg":  "RS256",
				"use":  "sig",
			}

			Expect(createKey(b, storage, entry)).NotTo(HaveLogicalError())

			req := &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("keys/%s", keyName),
			}

			resp, err := b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("public_key", Not(BeNil())))
		})
	})

	Describe("create/delete/read keys/:name", func() {

		It("should round trip asymmetric key", func() {
			entry := map[string]interface{}{
				"name": keyName,
				"alg":  "RS256",
				"use":  "sig",
			}

			Expect(createKey(b, storage, entry)).NotTo(HaveLogicalError())

			req := &logical.Request{
				Storage:   storage,
				Operation: logical.DeleteOperation,
				Path:      fmt.Sprintf("keys/%s", keyName),
			}

			resp, err := b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(HaveKeyWithValue("result", ContainSubstring("deleted")))

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("keys/%s", keyName),
			})

			Expect(resp, err).To(BeNil())
		})
	})

})
