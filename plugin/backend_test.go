package josejwt_test

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"

	// hold on to reference so dep doesn't lose it
	_ "github.com/SAP/go-hdb/driver"

	"github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
)

func testingFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := josejwt.Factory(context.Background(), config)
	return b, err
}

var _ = Describe("BackendTests", func() {

	It("should create and validate JWT", func() {
		keySetName := "test-key"
		roleName := "test-role"

		token := new(string)

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{

			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccAddGeneratedKeyToSet(keySetName, "key", "RS256", "sig"),
				testAccCreateRole(roleName, keySetName),
				testAccCreateJWT(roleName, token),
			},
		})
	})

	It("should read JWKS", func() {
		keySetName := "test-key-set"
		roleName := "test-role"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{

			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccAddGeneratedKeyToSet(keySetName, "key", "RS256", "sig"),
				testAccCreateRole(roleName, keySetName),
				testAccReadJWKSForRole(roleName),
			},
		})
	})

})

func testAccCreateRole(roleName, keySetName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("roles", roleName),
		Data: map[string]interface{}{
			"name":    roleName,
			"key_set": keySetName,
			"iss":     "http://127.0.0.1:8200/",
			"aud":     "vandelay",
			"sub":     "user",
			"type":    "jwt",
			// allow custom 'exp' to let us create expired tokens
			"allowed_custom_claims": []string{"exp", "overridable"},
		},
	}
}

func testAccReadJWKSForRole(roleName string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ReadOperation,
		Unauthenticated: true,
		Path:            path.Join("roles/jwks", roleName),
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
		Path:      path.Join("jwt/issue", roleName),
		Data: map[string]interface{}{
			"name": roleName,
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

			*token = tokenString
			return nil

		},
	}
}

func testAccCreateExpiredJWT(roleName string, token *string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("jwt/issue", roleName),
		Data: map[string]interface{}{
			"name": roleName,
			"claims": map[string]interface{}{
				"exp": time.Now().Add(-5 * time.Minute).Unix(),
			},
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

			*token = tokenString
			return nil

		},
	}
}
