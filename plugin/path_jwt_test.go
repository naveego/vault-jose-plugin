package josejwt_test

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jose "gopkg.in/square/go-jose.v2"

	//	. "github.com/naveego/vault-jose-plugin/plugin"

	"github.com/SermoDigital/jose/jws"

	"github.com/hashicorp/vault/sdk/logical"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
)

const (
	customClaimTye                = "custom"
	customClaimValue              = "custom-value"
	overridableClaimType          = "overridable"
	overridableClaimInitialValue  = "overridable-value"
	overridableClaimExpectedValue = "overridden-value"
)

var _ = Describe("PathIssue", func() {

	var (
		b        logical.Backend
		storage  logical.Storage
		roleData map[string]interface{}
		roleName string
	)

	BeforeEach(func() {
		roleName = "test-role"
		b, storage = getTestBackend()
		Expect(createSigningKeyForAlg(b, storage, "test-key-set", "test-key", string(jose.HS256))).ToNot(HaveLogicalError())

		roleData = map[string]interface{}{
			"name": roleName,
			"allowed_custom_claims": []string{"overridable",
				"exp"},
			"iss":           "test-issuer",
			"aud":           "test-audience",
			"nbf":           true,
			"key_set":       "test-key-set",
			"max_token_ttl": "100s",
			"sub":           "test-subject",
			"token_ttl":     "5s",
			"exp":           true,
			"type":          "jwt",
			"claims": map[string]interface{}{
				customClaimTye:       customClaimValue,
				overridableClaimType: overridableClaimInitialValue,
			},
			"iat": true,
		}

		Expect(createRole(b, storage, roleData)).ToNot(HaveLogicalError())

	})

	Describe("jwt/issue/:role", func() {

		It("should issue token", func() {

			resp, err := createToken(b, storage, roleName, time.Second*10, map[string]interface{}{
				overridableClaimType: overridableClaimExpectedValue,
				customClaimTye:       "not-allowed-value",
			})
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("token", BeAssignableToTypeOf("")))

			token := resp.Data["token"].(string)
			jwt, err := jws.ParseJWT([]byte(token))
			Expect(err).ToNot(HaveOccurred())

			fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
			Expect(jwt.Claims()).To(
				And(
					HaveKeyWithValue("aud", ContainElement("test-audience")),
					HaveKeyWithValue("sub", roleData["sub"]),
					HaveKeyWithValue("iss", roleData["iss"]),
					HaveKeyWithValue(customClaimTye, customClaimValue),
					HaveKeyWithValue(overridableClaimType, overridableClaimExpectedValue),
					HaveKeyWithValue("nbf", BeFloatTimestampCloseTo(fiveMinutesAgo, time.Second)),
					HaveKeyWithValue("iat", BeFloatTimestampCloseTo(time.Now(), time.Second)),
					HaveKeyWithValue("exp", BeFloatTimestampCloseTo(time.Now().Add(time.Second*10), time.Second)),
				))
		})
	})

	Describe("token/validate/:role", func() {

		It("should return is_valid=true if token is valid for generated key", func() {

			keySetName := "test-key"
			roleName := "test-role"

			token := new(string)

			logicaltest.Test(GinkgoT(), logicaltest.TestCase{

				Factory: testingFactory,
				Steps: []logicaltest.TestStep{
					testAccAddGeneratedKeyToSet(keySetName, "key", "RS256", "sig"),
					testAccCreateRole(roleName, keySetName),
					testAccCreateJWT(roleName, token),
					testAccValidateJWT(roleName, token, true),
				},
			})
		})

		It("should return is_valid=true if token is valid for provided key", func() {

			keySetName := "test-key"
			roleName := "test-role"

			token := new(string)

			logicaltest.Test(GinkgoT(), logicaltest.TestCase{

				Factory: testingFactory,
				Steps: []logicaltest.TestStep{
					testAccAddKeyToSet(keySetName, "key", "RS256", "sig", "pem", []byte(rsaPEM)),
					testAccCreateRole(roleName, keySetName),
					testAccCreateJWT(roleName, token),
					testAccValidateJWT(roleName, token, true),
				},
			})
		})

		It("should return is_valid=false and error=... if token is expired", func() {
			keySetName := "test-key"
			roleName := "test-role"

			token := new(string)

			logicaltest.Test(GinkgoT(), logicaltest.TestCase{

				Factory: testingFactory,
				Steps: []logicaltest.TestStep{
					testAccAddGeneratedKeyToSet(keySetName, "key", "RS256", "sig"),
					testAccCreateRole(roleName, keySetName),
					testAccCreateExpiredJWT(roleName, token),
					testAccValidateJWT(roleName, token, false),
				},
			})
		})
	})
})

// create the token given the parameters
func createToken(b logical.Backend, storage logical.Storage, roleName string, ttl time.Duration, claims map[string]interface{}) (*logical.Response, error) {
	data := map[string]interface{}{
		"role":      roleName,
		"token_ttl": ttl.Seconds(),
	}

	// set the claims to use if specified
	if claims != nil {
		data["claims"] = claims
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("jwt/issue/%s", roleName),
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)

	return resp, err
}

func testAccValidateJWT(roleName string, token *string, expectValid bool) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      path.Join("jwt/validate", roleName),
		Data: map[string]interface{}{
			"name": roleName,
		},
		PreFlight: func(req *logical.Request) error {

			jwt, err := jws.ParseJWT([]byte(*token))
			Expect(err).ToNot(HaveOccurred())
			exp, _ := jwt.Claims().Expiration()
			fmt.Printf("token expires: %s", exp)

			req.Data["token"] = *token
			return nil
		},
		Check: func(resp *logical.Response) error {

			isValid := resp.Data["is_valid"].(bool)

			if isValid {
				if expectValid {
					return nil
				}
				return errors.New("expected token to be invalid but it was valid")
			}

			if expectValid {
				return errors.New("expected token to be valid but it was invalid")
			}

			err := resp.Data["error"].(string)
			if err == "" {
				return errors.New("token was invalid but error was set")
			}

			return nil
		},
	}
}
