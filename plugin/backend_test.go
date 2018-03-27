package josejwt

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"

	// hold on to reference so dep doesn't lose it
	_ "github.com/SAP/go-hdb/driver"

	. "github.com/onsi/ginkgo"
)

func testingFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	return b, err
}

var _ = Describe("BackendTests", func() {

	It("should create and validate JWT", func() {
		keyName := "test-key"
		roleName := "test-role"

		var token *string

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{

			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateGeneratedRSAKey(keyName),
				testAccCreateRole(roleName, keyName),
				testAccCreateJWT(roleName, token),
			},
		})
	})

	It("should read JWKS", func() {
		keyName := "test-key"
		roleName := "test-role"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{

			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateGeneratedRSAKey(keyName),
				testAccCreateRole(roleName, keyName),
				testAccReadJWKS(roleName),
			},
		})
	})

})

func testAccCreateGeneratedRSAKey(name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("keys", name),
		Data: map[string]interface{}{
			"name": name,
			"alg":  string(jose.RS256),
			"use":  "sig",
		},
	}
}

func testAccCreateRole(roleName, keyName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("roles", roleName),
		Data: map[string]interface{}{
			"name": roleName,
			"key":  keyName,
			"iss":  "http://127.0.0.1:8200/",
			"aud":  "vandelay",
			"sub":  "user",
			"type": "jwt",
		},
	}
}

func testAccReadJWKS(roleName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ReadOperation,
		Unauthenticated: true,
		Path:            path.Join("jwks", roleName),
		Check: func(resp *logical.Response) error {

			bodyJSON, _ := json.Marshal(resp.Data)

			var keySet jose.JSONWebKeySet

			err := json.Unmarshal(bodyJSON, &keySet)

			if err != nil {
				return fmt.Errorf("error unmarshalling keyset: %s", err)
			}

			if len(keySet.Keys) == 0 {
				return errors.New("no keys in keyset")
			}

			return nil
		},
	}
}

func testAccCreateJWT(roleName string, token *string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("token/issue", roleName),
		Data: map[string]interface{}{
			"name": roleName,
			"iss":  "http://127.0.0.1:8200/",
			"aud":  "vandelay",
			"sub":  "user",
			"type": "jwt",
		},
		Check: func(resp *logical.Response) error {

			tokenRaw, ok := resp.Data["token"]
			if !ok {
				return errors.New("token was missing from data")
			}

			tokenString, ok := tokenRaw.(string)
			if !ok {
				return errors.New("token was not a string")
			}

			token = &tokenString
			return nil

		},
	}
}
