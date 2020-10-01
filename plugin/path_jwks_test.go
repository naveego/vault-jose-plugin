package josejwt_test

import (
	"errors"
	"fmt"
	"path"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/json"

	"github.com/hashicorp/vault/sdk/logical"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"

	// hold on to reference so dep doesn't lose it
	_ "github.com/SAP/go-hdb/driver"

	. "github.com/onsi/ginkgo"
)

const rsaPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAslWybuiNYR7uOgKuvaBwqVk8saEutKhOAaW+3hWF65gJei+Z
V8QFfYDxs9ZaRZlWAUMtncQPnw7ZQlXO9ogN5cMcN50C6qMOOZzghK7danalhF5l
UETC4Hk3Eisbi/PR3IfVyXaRmqL6X66MKj/JAKyD9NFIDVy52K8A198Jojnrw2+X
XQW72U68fZtvlyl/BTBWQ9Re5JSTpEcVmpCR8FrFc0RPMBm+G5dRs08vvhZNiTT2
JACO5V+J5ZrgP3s5hnGFcQFZgDnXLInDUdoi1MuCjaAU0ta8/08pHMijNix5kFof
dPEB954MiZ9k4kQ5/utt02I9x2ssHqw71ojjvwIDAQABAoIBABrYDYDmXom1BzUS
PE1s/ihvt1QhqA8nmn5i/aUeZkc9XofW7GUqq4zlwPxKEtKRL0IHY7Fw1s0hhhCX
LA0uE7F3OiMg7lR1cOm5NI6kZ83jyCxxrRx1DUSO2nxQotfhPsDMbaDiyS4WxEts
0cp2SYJhdYd/jTH9uDfmt+DGwQN7Jixio1Dj3vwB7krDY+mdre4SFY7Gbk9VxkDg
LgCLMoq52m+wYufP8CTgpKFpMb2/yJrbLhuJxYZrJ3qd/oYo/91k6v7xlBKEOkwD
2veGk9Dqi8YPNxaRktTEjnZb6ybhezat93+VVxq4Oem3wMwou1SfXrSUKtgM/p2H
vfw/76ECgYEA2fNL9tC8u9M0wjA+kvvtDG96qO6O66Hksssy6RWInD+Iqk3MtHQt
LeoCjvX+zERqwOb6SI6empk5pZ9E3/9vJ0dBqkxx3nqn4M/nRWnExGgngJsL959t
f50cdxva8y1RjNhT4kCwTrupX/TP8lAG8SfG1Alo2VFR8iWd8hDQcTECgYEA0Xfj
EgqAsVh4U0s3lFxKjOepEyp0G1Imty5J16SvcOEAD1Mrmz94aSSp0bYhXNVdbf7n
Rk77htWC7SE29fGjOzZRS76wxj/SJHF+rktHB2Zt23k1jBeZ4uLMPMnGLY/BJ099
5DTGo0yU0rrPbyXosx+ukfQLAHFuggX4RNeM5+8CgYB7M1J/hGMLcUpjcs4MXCgV
XXbiw2c6v1r9zmtK4odEe42PZ0cNwpY/XAZyNZAAe7Q0stxL44K4NWEmxC80x7lX
ZKozz96WOpNnO16qGC3IMHAT/JD5Or+04WTT14Ue7UEp8qcIQDTpbJ9DxKk/eglS
jH+SIHeKULOXw7fSu7p4IQKBgBnyVchIUMSnBtCagpn4DKwDjif3nEY+GNmb/D2g
ArNiy5UaYk5qwEmV5ws5GkzbiSU07AUDh5ieHgetk5dHhUayZcOSLWeBRFCLVnvU
i0nZYEZNb1qZGdDG8zGcdNXz9qMd76Qy/WAA/nZT+Zn1AiweAovFxQ8a/etRPf2Z
DbU1AoGAHpCgP7B/4GTBe49H0AQueQHBn4RIkgqMy9xiMeR+U+U0vaY0TlfLhnX+
5PkNfkPXohXlfL7pxwZNYa6FZhCAubzvhKCdUASivkoGaIEk6g1VTVYS/eDVQ4CA
slfl+elXtLq/l1kQ8C14jlHrQzSXx4PQvjDEnAmaHSJNz4mP9Fg=
-----END RSA PRIVATE KEY-----`

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

	It("should set key from PEM", func() {
		keySetName := "test-key-set"
		keyID := "test-key-id"

		logicaltest.Test(GinkgoT(), logicaltest.TestCase{
			Factory: testingFactory,
			Steps: []logicaltest.TestStep{
				testAccCreateKeySet(keySetName),
				testAccListKeySets(keySetName),
				testAccAddKeyToSet(keySetName, keyID, "RS256", "sig", "pem", []byte(rsaPEM)),
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
				testAccListKeys(keySetName, 3),
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

	It("should set active key when it exists", func() {
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

func testAccListKeys(keySetName string, keyCount int) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ListOperation,
		Path:      path.Join("jwks", keySetName),
		Check: func(resp *logical.Response) error {

			keys := resp.Data["keys"].([]string)

			if len(keys) != keyCount {
				return fmt.Errorf("expected list to have %d entries but there were %d", keyCount, len(keys))
			}

			return nil
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

			for i, key := range keySet.Keys {
				if !key.Valid() {
					return fmt.Errorf("key at index %d was invalid", i)
				}
				if !key.IsPublic() {
					return fmt.Errorf("KEY AT INDEX %d INCLUDED PRIVATE KEY DATA", i)
				}
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

func testAccAddKeyToSet(keySetName, kid, alg, use, encoding string, data []byte) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.CreateOperation,
		Path:      path.Join("jwks", keySetName, kid),
		Data: map[string]interface{}{
			"key_set_name": keySetName,
			"kid":          kid,
			"alg":          alg,
			"use":          use,
			encoding:       string(data),
		},
	}
}
