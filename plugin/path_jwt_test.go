package josejwt_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jose "gopkg.in/square/go-jose.v2"

	//	. "github.com/naveego/vault-jose-plugin/plugin"

	"github.com/SermoDigital/jose/jws"

	"github.com/hashicorp/vault/logical"
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
		keyEntry map[string]interface{}
		roleData map[string]interface{}
		roleName string
	)

	BeforeEach(func() {
		roleName = "test-role"
		b, storage = getTestBackend()
		keyEntry = map[string]interface{}{
			"name": keyName,
			"jwk":  jose.JSONWebKey{Key: []byte("test-key"), Algorithm: string(jose.HS256)},
		}
		Expect(createKey(b, storage, keyEntry)).ToNot(HaveLogicalError())

		roleData = map[string]interface{}{
			"name": roleName,
			"allowed_custom_claims": []string{"overridable",
				"exp"},
			"iss":           "test-issuer",
			"aud":           "test-audience",
			"nbf":           true,
			"key":           "test-key",
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

			Expect(jwt.Claims()).To(
				And(
					HaveKeyWithValue("aud", ContainElement("test-audience")),
					HaveKeyWithValue("sub", roleData["sub"]),
					HaveKeyWithValue("iss", roleData["iss"]),
					HaveKeyWithValue(customClaimTye, customClaimValue),
					HaveKeyWithValue(overridableClaimType, overridableClaimExpectedValue),
					HaveKeyWithValue("nbf", BeFloatTimestampCloseTo(time.Now(), time.Second)),
					HaveKeyWithValue("iat", BeFloatTimestampCloseTo(time.Now(), time.Second)),
					HaveKeyWithValue("exp", BeFloatTimestampCloseTo(time.Now().Add(time.Second*10), time.Second)),
				))
		})
	})

	Describe("token/validate/:role", func() {

		It("should return is_valid=true if token is valid", func() {
			resp, err := createToken(b, storage, roleName, time.Second*10, nil)
			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(HaveKeyWithValue("token", BeAssignableToTypeOf("")))
			token := resp.Data["token"].(string)

			req := &logical.Request{
				Storage: storage,
				Data: map[string]interface{}{
					"token": token,
					"role":  roleName,
				},
				Path:      fmt.Sprintf("jwt/validate/%s", roleName),
				Operation: logical.UpdateOperation,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("is_valid", true))
		})

		It("should return is_valid=false and error=... if token is expired", func() {
			exp := time.Now().Add(time.Hour * -1000)
			resp, err := createToken(b, storage, roleName, time.Second*1, map[string]interface{}{
				"exp": exp.Unix(),
			})

			Expect(resp, err).ToNot(HaveLogicalError())
			Expect(resp.Data).To(HaveKeyWithValue("token", BeAssignableToTypeOf("")))
			token := resp.Data["token"].(string)

			req := &logical.Request{
				Storage: storage,
				Data: map[string]interface{}{
					"token": token,
					"role":  roleName,
				},
				Path:      fmt.Sprintf("jwt/validate/%s", roleName),
				Operation: logical.UpdateOperation,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("is_valid", false))
			Expect(resp.Data).To(HaveKeyWithValue("error", ContainSubstring("token is expired")))
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
