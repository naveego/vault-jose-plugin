package josejwt_test

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PathConfig", func() {

	var (
		b       logical.Backend
		storage logical.Storage
	)

	BeforeEach(func() {
		b, storage = getTestBackend()
	})

	Describe("update+read /config", func() {

		It("should round trip config urls", func() {
			entry := map[string]interface{}{
				"base_url": "http://example.com/",
			}

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "config/urls",
				Data:      entry,
			})
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(BeEquivalentTo(entry))

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      "config/urls",
			})
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(BeEquivalentTo(entry))
		})
	})
})
