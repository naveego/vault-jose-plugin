package josejwt_test

import (
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	//. "github.com/onsi/ginkgo/extensions/table"

	. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/types"
)

var _ = Describe("ValidateJWTToken", func() {

	Describe("based on signature", func() {

		getJWT := func(t TokenCreateEntry, r RoleStorageEntry, k jose.JSONWebKey) string {
			actualBytes, err := CreateJWTToken(t, r, k)
			Expect(err).ToNot(HaveOccurred())

			return string(actualBytes)
		}

		It("should support hs*", func() {
			key := KeyStorageEntry{
				Name: "test-key",
				PrivateKey: &jose.JSONWebKey{
					Key:       []byte("test-key"),
					Algorithm: string(jose.HS256),
				},
			}

			role := RoleStorageEntry{
				Name:           "test-role",
				Type:           "jwt",
				Key:            key.Name,
				TokenTTL:       time.Second * 100,
				ExpirationTime: true,
			}

			actual := getJWT(TokenCreateEntry{
				Role: role.Name,
			}, role, key)

			Expect(ValidateJWTToken(actual, role, *key.PrivateKey)).To(Succeed())
		})

		It("should support rs*", func() {

			key := KeyStorageEntry{
				Name: "test-key",
			}

			Expect(GeneratePublicAndPrivateKeys(&key, string(jose.RS256), "sig")).To(Succeed())

			role := RoleStorageEntry{
				Name:           "test-role",
				Type:           "jwt",
				Key:            key.Name,
				TokenTTL:       100,
				ExpirationTime: true,
			}

			actual := getJWT(TokenCreateEntry{
				Role: role.Name,
			}, role, key)

			Expect(ValidateJWTToken(actual, role, *key.PrivateKey)).To(Succeed())
		})
	})

})

var _ = Describe("CreateJWTToken", func() {

	Describe("signing", func() {

		getJWT := func(t TokenCreateEntry, r RoleStorageEntry, k jose.JSONWebKey) (claims jwt.Claims, privateClaims map[string]interface{}) {
			actualBytes, err := CreateJWTToken(t, r, k)
			Expect(err).ToNot(HaveOccurred())

			actual, err := jwt.ParseSigned(string(actualBytes))
			Expect(err).ToNot(HaveOccurred())
			if k.PrivateKey.Algorithm == string(jose.HS256) {
				Expect(actual.Claims(k, &claims, &privateClaims)).To(Succeed())
			} else {
				Expect(actual.Claims(k.Public(), &claims, &privateClaims)).To(Succeed())
			}

			return
		}

		It("should support hs*", func() {
			key := KeyStorageEntry{
				Name: "test-key",
				PrivateKey: &jose.JSONWebKey{
					Key:       []byte("test-key"),
					Algorithm: string(jose.HS256),
				},
			}

			role := RoleStorageEntry{
				Name:           "test-role",
				Type:           "jwt",
				Key:            key.Name,
				TokenTTL:       100,
				ExpirationTime: true,
			}

			claims, privateClaims := getJWT(TokenCreateEntry{
				Role: role.Name,
			}, role, *key.PrivateKey)
			Expect(claims).ToNot(BeNil())
			Expect(privateClaims).ToNot(BeNil())

		})

		It("should support rs*", func() {

			key := KeyStorageEntry{
				Name: "test-key",
			}

			Expect(GeneratePublicAndPrivateKeys(&key, string(jose.RS256), "sig")).To(Succeed())

			role := RoleStorageEntry{
				Name:           "test-role",
				Type:           "jwt",
				Key:            key.Name,
				TokenTTL:       100,
				ExpirationTime: true,
			}

			claims, privateClaims := getJWT(TokenCreateEntry{
				Role: role.Name,
			}, role, *key.PrivateKey)
			Expect(claims).ToNot(BeNil())
			Expect(privateClaims).ToNot(BeNil())
		})

	})

	Describe("setting claims", func() {
		var (
			key  KeyStorageEntry
			role RoleStorageEntry
		)

		getJWT := func(t TokenCreateEntry, r RoleStorageEntry, k jose.JSONWebKey) (claims jwt.Claims, privateClaims map[string]interface{}) {
			actualBytes, err := CreateJWTToken(t, r, k)
			Expect(err).ToNot(HaveOccurred())

			actual, err := jwt.ParseSigned(string(actualBytes))
			Expect(err).ToNot(HaveOccurred())

			Expect(actual.Claims(k.PrivateKey.Key, &claims, &privateClaims)).To(Succeed())
			return
		}

		BeforeEach(func() {

			key = KeyStorageEntry{
				Name: "test-key",
				PrivateKey: &jose.JSONWebKey{
					Key:       []byte("test-key"),
					Algorithm: string(jose.HS256),
				},
			}

			role = RoleStorageEntry{
				Name: "test-role",
				Type: "jwt",
				Key:  key.Name,

				Issuer:         "test-issuer",
				Subject:        "test-subject",
				Audience:       "test-audience",
				NotBefore:      true,
				ExpirationTime: true,
				IssuedAt:       true,
				TokenTTL:       100,
				MaxTokenTTL:    100,
			}
		})

		It("should sign token and set all registered claims", func() {

			claims, _ := getJWT(TokenCreateEntry{
				Role: role.Name,
			}, role, key)

			Expect(claims.Validate(jwt.Expected{
				Audience: []string{role.Audience},
				Subject:  role.Subject,
				Issuer:   role.Issuer,
				Time:     time.Now(),
			}))

			Expect(claims.NotBefore.Time()).To(BeTemporally("~", time.Now(), time.Second))
			Expect(claims.IssuedAt.Time()).To(BeTemporally("~", time.Now(), time.Second))
			Expect(claims.Expiry.Time()).To(BeTemporally("~", time.Now().Add(role.TokenTTL), time.Second))
		})

		Describe("custom claims in role", func() {

			BeforeEach(func() {
				role.Claims = map[string]interface{}{
					"custom":      "original-custom-value",
					"overridable": "original-overridable-value",
				}
				role.AllowedCustomClaims = []string{"overridable"}
			})

			It("should place custom claims in role", func() {
				_, privateClaims := getJWT(TokenCreateEntry{
					Role: role.Name,
				}, role, key)

				Expect(privateClaims).To(
					And(
						HaveKeyWithValue("custom", "original-custom-value"),
						HaveKeyWithValue("overridable", "original-overridable-value"),
					))
			})

			It("should assign allowed custom claims from request to token", func() {
				_, privateClaims := getJWT(TokenCreateEntry{
					Role: role.Name,
					Claims: map[string]interface{}{
						"overridable": "overridden-value",
					},
				}, role, key)
				Expect(privateClaims).To(
					And(
						HaveKeyWithValue("custom", "original-custom-value"),
						HaveKeyWithValue("overridable", "overridden-value"),
					))
			})

			It("should not assign disallowed custom claims from request to token", func() {
				_, privateClaims := getJWT(TokenCreateEntry{
					Role: role.Name,
					Claims: map[string]interface{}{
						"custom": "overridden-value",
					},
				}, role, key)
				Expect(privateClaims).To(
					HaveKeyWithValue("custom", "original-custom-value"),
				)
			})
		})
	})

})

func BeFloatTimestampCloseTo(t time.Time, threshold ...time.Duration) GomegaMatcher {
	return WithTransform(func(i float64) time.Time {
		return time.Unix(int64(i), 0)
	}, BeTemporally("~", t, threshold...))
}
