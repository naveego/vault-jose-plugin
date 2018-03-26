package josejwt_test

import (
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	//. "github.com/onsi/ginkgo/extensions/table"

	. "github.com/naveego/vault-jose-plugin/plugin"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/types"
)

var _ = Describe("ValidateJWTToken", func() {

	Describe("based on signature", func() {

		getJWT := func(t TokenCreateEntry, r RoleStorageEntry, k KeyStorageEntry) string {
			actualBytes, err := CreateJWTToken(t, r, k)
			Expect(err).ToNot(HaveOccurred())

			return string(actualBytes)
		}

		It("should support hs*", func() {
			key := KeyStorageEntry{
				Name:       "test-key",
				Algorithm:  crypto.SigningMethodHS256.Name,
				PrivateKey: "test-key",
			}

			role := RoleStorageEntry{
				Name:     "test-role",
				Type:     "jwt",
				Key:      key.Name,
				TokenTTL: time.Second * 100,
			}

			actual := getJWT(TokenCreateEntry{
				RoleName: role.Name,
			}, role, key)

			Expect(ValidateJWTToken(actual, role, key)).To(Succeed())
		})

		It("should support rs*", func() {

			key := KeyStorageEntry{
				Name:      "test-key",
				Algorithm: crypto.SigningMethodRS256.Name,
			}

			Expect(GeneratePublicAndPrivateKeys(&key)).To(Succeed())

			role := RoleStorageEntry{
				Name:     "test-role",
				Type:     "jwt",
				Key:      key.Name,
				TokenTTL: 100,
			}

			actual := getJWT(TokenCreateEntry{
				RoleName: role.Name,
			}, role, key)

			Expect(ValidateJWTToken(actual, role, key)).To(Succeed())
		})
	})

})

var _ = Describe("CreateJWTToken", func() {

	Describe("signing", func() {

		getJWT := func(t TokenCreateEntry, r RoleStorageEntry, k KeyStorageEntry) jwt.JWT {
			actualBytes, err := CreateJWTToken(t, r, k)
			Expect(err).ToNot(HaveOccurred())

			actual, err := jws.ParseJWT(actualBytes)
			Expect(err).ToNot(HaveOccurred())
			return actual
		}

		It("should support hs*", func() {
			key := KeyStorageEntry{
				Name:       "test-key",
				Algorithm:  crypto.SigningMethodHS256.Name,
				PrivateKey: "test-key",
			}

			role := RoleStorageEntry{
				Name:     "test-role",
				Type:     "jwt",
				Key:      key.Name,
				TokenTTL: 100,
			}

			actual := getJWT(TokenCreateEntry{
				RoleName: role.Name,
			}, role, key)

			signingMethod := jws.GetSigningMethod(key.Algorithm)
			Expect(actual.Validate([]byte(key.PrivateKey), signingMethod)).To(Succeed())
		})

		It("should support rs*", func() {

			key := KeyStorageEntry{
				Name:      "test-key",
				Algorithm: crypto.SigningMethodRS256.Name,
			}

			Expect(GeneratePublicAndPrivateKeys(&key)).To(Succeed())

			role := RoleStorageEntry{
				Name:     "test-role",
				Type:     "jwt",
				Key:      key.Name,
				TokenTTL: 100,
			}

			actual := getJWT(TokenCreateEntry{
				RoleName: role.Name,
			}, role, key)

			signingMethod := jws.GetSigningMethod(key.Algorithm)
			publicKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(key.PublicKey))
			Expect(err).ToNot(HaveOccurred())
			Expect(actual.Validate(publicKey, signingMethod)).To(Succeed())
		})

		// DescribeTable("elliptic curve", func(method string) {

		// 	key := KeyStorageEntry{
		// 		Name:      "test-key",
		// 		Algorithm: method,
		// 	}

		// 	Expect(GeneratePublicAndPrivateKeys(&key)).To(Succeed())

		// 	role := RoleStorageEntry{
		// 		Name:     "test-role",
		// 		Type:     "jwt",
		// 		Key:      key.Name,
		// 		TokenTTL: 100,
		// 	}

		// 	actual := getJWT(TokenCreateEntry{
		// 		RoleName: role.Name,
		// 	}, role, key)

		// 	signingMethod := jws.GetSigningMethod(key.Algorithm)
		// 	publicKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(key.PublicKey))
		// 	Expect(err).ToNot(HaveOccurred())
		// 	Expect(actual.Validate(publicKey, signingMethod)).To(Succeed())
		// },
		// 	Entry("EC256", crypto.SigningMethodES256.Name),
		// 	Entry("EC384", crypto.SigningMethodES384.Name),
		// 	Entry("EC512", crypto.SigningMethodES512.Name),
		// )
	})

	Describe("setting claims", func() {
		var (
			key  KeyStorageEntry
			role RoleStorageEntry
		)

		getJWT := func(t TokenCreateEntry) jwt.JWT {
			actualBytes, err := CreateJWTToken(t, role, key)
			Expect(err).ToNot(HaveOccurred())

			actual, err := jws.ParseJWT(actualBytes)
			Expect(err).ToNot(HaveOccurred())
			return actual
		}

		BeforeEach(func() {

			key = KeyStorageEntry{
				Name:       "test-key",
				Algorithm:  crypto.SigningMethodHS256.Name,
				PrivateKey: "test-key",
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

			actual := getJWT(TokenCreateEntry{
				RoleName: role.Name,
			})

			claims := actual.Claims()

			Expect(claims).To(And(HaveKeyWithValue("aud", role.Audience),
				HaveKeyWithValue("sub", role.Subject),
				HaveKeyWithValue("iss", role.Issuer),
				HaveKey("jti"),
				HaveKeyWithValue("exp", BeFloatTimestampCloseTo(time.Now().Add(role.TokenTTL), time.Second)),
				HaveKeyWithValue("nbf", BeFloatTimestampCloseTo(time.Now(), time.Second)),
				HaveKeyWithValue("iat", BeFloatTimestampCloseTo(time.Now(), time.Second)),
			))
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
				actual := getJWT(TokenCreateEntry{
					RoleName: role.Name,
				})
				Expect(actual.Claims()).To(
					And(
						HaveKeyWithValue("custom", "original-custom-value"),
						HaveKeyWithValue("overridable", "original-overridable-value"),
					))
			})

			It("should assign allowed custom claims from request to token", func() {
				actual := getJWT(TokenCreateEntry{
					RoleName: role.Name,
					Claims: map[string]interface{}{
						"overridable": "overridden-value",
					},
				})
				Expect(actual.Claims()).To(
					And(
						HaveKeyWithValue("custom", "original-custom-value"),
						HaveKeyWithValue("overridable", "overridden-value"),
					))
			})

			It("should not assign disallowed custom claims from request to token", func() {
				actual := getJWT(TokenCreateEntry{
					RoleName: role.Name,
					Claims: map[string]interface{}{
						"custom": "overridden-value",
					},
				})
				Expect(actual.Claims()).To(
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
