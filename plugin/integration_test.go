// +build integration

package josejwt_test

import (
	"os"

	"github.com/hashicorp/go-uuid"

	"github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	//. "github.com/naveego/vault-jose-plugin/plugin"
)

var (
	vaultAddr  string
	vaultToken string
)

func init() {
	var ok bool
	if vaultAddr, ok = os.LookupEnv("VAULT_ADDR"); !ok {
		vaultAddr = "http://127.0.0.1:8200"
	}
	if vaultToken, ok = os.LookupEnv("VAULT_TOKEN"); !ok {
		vaultToken = "root"
	}
}

var _ = Describe("Integration", func() {

	var (
		client   *api.Client
		err      error
		keyName  string
		roleName string
	)

	BeforeEach(func() {
		config := api.DefaultConfig()
		config.Address = vaultAddr
		client, err = api.NewClient(config)
		Expect(err).ToNot(HaveOccurred())
		client.SetToken(vaultToken)

		keyName, _ = uuid.GenerateUUID()
		roleName, _ = uuid.GenerateUUID()
	})

	AfterEach(func() {
		l := client.Logical()

		_, _ = l.Delete("jose/keys/" + keyName)
		_, _ = l.Delete("jose/roles/" + roleName)
	})

	It("should create and validate symmetric JWT", func() {

		l := client.Logical()
		Expect(l.Write("jose/keys/"+keyName, map[string]interface{}{
			"alg": "HS256",
		})).ToNot(BeNil())

		Expect(l.Write("jose/roles/"+roleName, map[string]interface{}{
			"key":  keyName,
			"iss":  "http://127.0.0.1:8200/",
			"aud":  "vandelay",
			"sub":  "user",
			"type": "jwt",
		})).ToNot(BeNil())

		s, err := l.Write("jose/token/issue/"+roleName, map[string]interface{}{})
		Expect(err).ToNot(HaveOccurred())

		Expect(s.Data).To(HaveKey("token"))

		token := s.Data["token"].(string)

		validation, err := l.Write("jose/token/validate/"+roleName, map[string]interface{}{
			"token": token,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(validation.Data).To(HaveKeyWithValue("is_valid", true))
	})

})
