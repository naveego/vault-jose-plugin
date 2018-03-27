package josejwt_test

import (
	"context"
	"fmt"
	"testing"

	"gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/types"
)

func TestPlugin(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Plugin Suite")
}

// return the mocked out backend for testing
func getTestBackend() (logical.Backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	Expect(err).ToNot(HaveOccurred())

	return b, config.StorageView
}

func createKey(b logical.Backend, storage logical.Storage, data map[string]interface{}) (*logical.Response, error) {

	key := data["jwk"]
	if key != nil {
		if webKey, ok := key.(jose.JSONWebKey); ok {
			raw, err := webKey.MarshalJSON()
			Expect(err).ToNot(HaveOccurred())

			Expect(webKey.UnmarshalJSON(raw)).To(Succeed())
			data["jwk"] = string(raw)
		}
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("keys/%s", data["name"]),
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	return resp, err
}

func createRole(b logical.Backend, storage logical.Storage, data map[string]interface{}) (*logical.Response, error) {

	delete(data, "role_id")

	fieldData := &framework.FieldData{
		Raw:    data,
		Schema: CreateRoleSchema,
	}

	Expect(fieldData.Validate()).To(Succeed())

	req := &logical.Request{
		Storage: storage,
	}

	req.Operation = logical.CreateOperation
	req.Path = fmt.Sprintf("roles/%s", data["name"])
	req.Data = data

	resp, err := b.HandleRequest(context.Background(), req)
	return resp, err
}

func HaveLogicalError() GomegaMatcher {
	return WithTransform(func(resp *logical.Response) error {
		return resp.Error()
	}, HaveOccurred())
}
