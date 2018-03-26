package josejwt_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	//	. "github.com/naveego/vault-jose-plugin/plugin"

	"github.com/SermoDigital/jose/crypto"
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
			"name":        keyName,
			"alg":         crypto.SigningMethodHS256.Name,
			"private_key": "test-key",
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

	Describe("token/issue/:role", func() {

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
					HaveKeyWithValue("aud", roleData["aud"]),
					HaveKeyWithValue("sub", roleData["sub"]),
					HaveKeyWithValue("iss", roleData["iss"]),
					HaveKeyWithValue(customClaimTye, customClaimValue),
					HaveKeyWithValue(overridableClaimType, overridableClaimExpectedValue),
					HaveKeyWithValue("nbf", BeFloatTimestampCloseTo(time.Now(), time.Second)),
					HaveKeyWithValue("iat", BeFloatTimestampCloseTo(time.Now(), time.Second)),
					HaveKeyWithValue("exp", BeFloatTimestampCloseTo(time.Now().Add(time.Second*10), time.Second)),
				))

			alg := jws.GetSigningMethod(keyEntry["alg"].(string))
			Expect(jwt.Validate([]byte(keyEntry["private_key"].(string)), alg)).To(Succeed())

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
					"token":     token,
					"role_name": roleName,
				},
				Path:      fmt.Sprintf("token/validate/%s", roleName),
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
					"token":     token,
					"role_name": roleName,
				},
				Path:      fmt.Sprintf("token/validate/%s", roleName),
				Operation: logical.UpdateOperation,
			}

			resp, err = b.HandleRequest(context.Background(), req)
			Expect(resp, err).ToNot(HaveLogicalError())

			Expect(resp.Data).To(HaveKeyWithValue("is_valid", false))
			Expect(resp.Data).To(HaveKeyWithValue("error", "token is expired"))
		})
	})
})

func TestIssueValidateToken(t *testing.T) {
	// TODO: implemented validation
	// b, storage := getTestBackend(t)
	// roleName := "test_role"
	// resp, _ := createSampleRole(b, storage, roleName, "")

	// req := &logical.Request{
	// 	Storage:     storage,
	// 	DisplayName: fmt.Sprintf("test-%s", roleName),
	// }

	// resp, err := createToken(req, b, t, roleName, "")
	// if err != nil || (resp != nil && resp.IsError()) {
	// 	t.Fatalf("err:%s resp:%#v\n", err, resp)
	// }

	// if resp.Data["ClientToken"] == "" {
	// 	t.Fatal("no token returned\n")
	// }

	// clientToken := resp.Data["ClientToken"].(string)
	// log.Println(clientToken)

	// // with a 1 second timeout this should still return a valid token
	// time.Sleep(time.Duration(1) * time.Second)
	// validateToken(req, b, t, clientToken, roleName, true)
	// validateToken(req, b, t, clientToken, roleName, true)

	// // with a two second timeout this should fail vaildation
	// time.Sleep(time.Duration(2) * time.Second)
	// validateToken(req, b, t, clientToken, roleName, false)

	// // now to recreate a token and test its valid once again
	// resp, err = createToken(req, b, t, roleName, "")
	// if err != nil || (resp != nil && resp.IsError()) {
	// 	t.Fatalf("err:%s resp:%#v\n", err, resp)
	// }

	// if resp.Data["ClientToken"] == "" {
	// 	t.Fatal("no token returned\n")
	// }

	// clientToken = resp.Data["ClientToken"].(string)
	// validateToken(req, b, t, clientToken, roleName, true)
}

// create the token given the parameters
func createToken(b logical.Backend, storage logical.Storage, roleName string, ttl time.Duration, claims map[string]interface{}) (*logical.Response, error) {
	data := map[string]interface{}{
		"role_name": roleName,
		"token_ttl": ttl.Seconds(),
	}

	// set the claims to use if specified
	if claims != nil {
		data["claims"] = claims
	}

	req := &logical.Request{
		Storage:   storage,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("token/issue/%s", roleName),
		Data:      data,
	}
	resp, err := b.HandleRequest(context.Background(), req)

	return resp, err
}
