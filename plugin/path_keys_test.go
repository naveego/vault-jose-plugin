package josejwt_test

import (
	"context"
	"fmt"

	"github.com/SermoDigital/jose/crypto"
	"github.com/hashicorp/vault/logical"
	"github.com/mitchellh/mapstructure"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	. "github.com/naveego/vault-jose-plugin/plugin"
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

	Describe("PUT+GET keys/:name", func() {

		It("should round trip keys without private key", func() {
			entry := map[string]interface{}{
				"name":        keyName,
				"alg":         crypto.SigningMethodHS256.Name,
				"private_key": "test-key",
			}
			Expect(createKey(b, storage, entry)).NotTo(HaveLogicalError())

			req := &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      fmt.Sprintf("keys/%s", keyName),
			}

			resp, err := b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			var returnedKey KeyStorageEntry
			err = mapstructure.Decode(resp.Data, &returnedKey)

			Expect(resp.Data).To(BeEquivalentTo(map[string]interface{}{
				"name":       keyName,
				"alg":        crypto.SigningMethodHS256.Name,
				"enc":        "",
				"public_key": "",
			}))

		})

	})

})
