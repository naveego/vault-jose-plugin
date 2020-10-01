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

		It("should round trip config", func() {
			entry := map[string]interface{}{
				"lease":     float64(7),
				"lease_max": float64(70),
			}

			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.UpdateOperation,
				Path:      "config/lease",
				Data:      entry,
			})
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(BeEquivalentTo(entry))

			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Storage:   storage,
				Operation: logical.ReadOperation,
				Path:      "config/lease",
			})
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(BeEquivalentTo(entry))
		})
	})
})
