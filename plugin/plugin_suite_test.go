package josejwt_test

import (
	"context"
	"fmt"
	"path"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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

func createSigningKeyForAlg(b logical.Backend, storage logical.Storage, keySetName, kid, alg string) (*logical.Response, error) {

	data := map[string]interface{}{
		"kid": kid,
		"alg": alg,
		"use": "sig",
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.CreateOperation,
		Path:      path.Join("jwks", keySetName, kid),
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
