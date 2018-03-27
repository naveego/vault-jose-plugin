package josejwt_test

import (
	"errors"
	"fmt"
	"path"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"

	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"

	// hold on to reference so dep doesn't lose it
	_ "github.com/SAP/go-hdb/driver"

	. "github.com/onsi/ginkgo"
)

var _ = Describe("/keysets", func() {

	It("should create key set and add key to it", func() {
		keySetName := "test-key-set"
		keyID := "test-key-id"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateKeySet(keySetName),
				testAccListKeySets(keySetName),
				testAccAddGeneratedKeyToSet(keySetName, keyID, "RS256", "sig"),
				testAccListKeysInKeySet(keySetName, keyID),
				testAccReadPublicKey(keySetName, keyID),
				testAccReadJWKS(keySetName, 1),
			},
		})
	})

	It("should only return jwks for public keys", func() {
		keySetName := "test-key-set"
		keyID := "test-key-id"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateKeySet(keySetName),
				testAccAddGeneratedKeyToSet(keySetName, keyID, "RS256", "sig"),
				testAccAddGeneratedKeyToSet(keySetName, "eckey", "ES256", "sig"),
				testAccAddGeneratedKeyToSet(keySetName, "symmetric-key", "HS256", "sig"),
				testAccReadJWKS(keySetName, 2),
			},
		})
	})

	It("first key added to set should be active", func() {
		keySetName := "test-key-set"
		keyID := "test-key-id"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateKeySet(keySetName),
				testAccAddGeneratedKeyToSet(keySetName, keyID, "RS256", "sig"),
				testAccCheckActiveKID(keySetName, keyID),
			},
		})
	})

	FIt("should set active key when it exists", func() {
		keySetName := "test-key-set"
		keyID1 := "test-key-id-1"
		keyID2 := "test-key-id-2"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateKeySet(keySetName),
				testAccAddGeneratedKeyToSet(keySetName, keyID1, "RS256", "sig"),
				testAccAddGeneratedKeyToSet(keySetName, keyID2, "RS256", "sig"),
				testAccSetActiveKID(keySetName, keyID2),
				testAccCheckActiveKID(keySetName, keyID2),
			},
		})
	})

	It("should create key set if it doesn't exist, and make new key the active key", func() {
		keySetName := "test-key-set"
		keyID := "test-key-id"
		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccAddGeneratedKeyToSet(keySetName, keyID, "RS256", "sig"),
				testAccListKeySets(keySetName),
				testAccListKeysInKeySet(keySetName, keyID),
				testAccCheckActiveKID(keySetName, keyID),
			},
		})
	})

})

func testAccCreateKeySet(name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      "jwks/" + name,
		Data: map[string]interface{}{
			"name": name,
		},
	}
}

func testAccListKeySets(name string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ListOperation,
		Path:      "jwks",
		Check: func(resp *logical.Response) error {
			items := resp.Data["keys"].([]string)

			for _, item := range items {
				if item == name {
					return nil
				}
			}

			return fmt.Errorf("did not find keyset name %q in data %#v", name, resp.Data)
		},
	}
}

func testAccReadJWKS(keySetName string, keyCount int) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation:       logical.ReadOperation,
		Unauthenticated: true,
		Path:            path.Join("jwks", keySetName, "public"),
		Check: func(resp *logical.Response) error {

			bodyJSON, _ := json.Marshal(resp.Data)

			var keySet jose.JSONWebKeySet

			err := json.Unmarshal(bodyJSON, &keySet)

			if err != nil {
				return fmt.Errorf("error unmarshalling keyset: %s", err)
			}

			if len(keySet.Keys) != keyCount {
				return fmt.Errorf("expected %d keys in key set but found %d", keyCount, len(keySet.Keys))
			}

			return nil
		},
	}
}
func testAccSetActiveKID(name string, kid string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      path.Join("jwks", name),
		Data: map[string]interface{}{
			"name":       name,
			"active_kid": kid,
		},
	}
}

func testAccCheckActiveKID(name string, kid string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      path.Join("jwks", name),
		Check: func(resp *logical.Response) error {
			activeKID := resp.Data["active_kid"].(string)
			if activeKID != kid {
				return fmt.Errorf("active_kid was %q but we expected %q", activeKID, kid)
			}

			return nil
		},
	}
}

func testAccListKeysInKeySet(keySetName, kid string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ListOperation,
		Path:      path.Join("jwks", keySetName),
		Check: func(resp *logical.Response) error {
			items := resp.Data["keys"].([]string)

			for _, item := range items {
				if item == kid {
					return nil
				}
			}

			return fmt.Errorf("did not find kid %q in data %#v", kid, resp.Data)
		},
	}
}

func testAccReadPublicKey(keySetName, kid string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      path.Join("jwks", keySetName, kid),
		Check: func(resp *logical.Response) error {
			jwkBytes := resp.Data["jwk"].([]byte)

			jwk := new(jose.JSONWebKey)
			err := jwk.UnmarshalJSON(jwkBytes)
			if err != nil {
				return err
			}

			if !jwk.Valid() {
				return errors.New("jwk was not valid")
			}

			return nil
		},
	}
}

func testAccAddGeneratedKeyToSet(keySetName, kid, alg, use string) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("jwks", keySetName, kid),
		Data: map[string]interface{}{
			"key_set_name": keySetName,
			"kid":          kid,
			"alg":          alg,
			"use":          use,
		},
	}
}
