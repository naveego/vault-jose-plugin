package josejwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/SermoDigital/jose/crypto"

	"github.com/hashicorp/vault/logical"
)

// KeyStorageEntry strutcure defines the type of object that is stored
type KeyStorageEntry struct {
	// the name of the private key
	Name string `json:"name" structs:"name" mapstructure:"name"`

	// the type of encryption to use
	Encryption string `json:"enc" structs:"enc" mapstructure:"enc"`

	// the algorithm that the encyrption uses
	Algorithm string `json:"alg" structs:"alg" mapstructure:"alg"`

	// private key can be generated or provided based on alg type
	PrivateKey string `json:"private_key" structs:"private_key" mapstructure:"private_key"`

	// Public key that can be sent to third parties
	PublicKey string `json:"public_key" structs:"public_key" mpastructure:"public_key"`

	// encrypted private key, created based on encyption type
	EncPrivateKey string `json:"enc_private_key" structs:"enc_private_key" mapstructure:"enc_private_key"`
}

func (backend *JwtBackend) getKeyEntry(ctx context.Context, storage logical.Storage, keyName string) (*KeyStorageEntry, error) {
	if keyName == "" {
		return nil, fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	lock := backend.keyLock(keyName)
	lock.RLock()
	defer lock.RUnlock()

	var result KeyStorageEntry
	if entry, err := storage.Get(ctx, fmt.Sprintf("keys/%s", keyName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Save the key entry to the local storage
func (backend *JwtBackend) setKeyEntry(ctx context.Context, storage logical.Storage, key KeyStorageEntry) error {
	if key.Name == "" {
		return fmt.Errorf("Unable to save key, invalid name")
	}

	keyName := strings.ToLower(key.Name)

	// TODO : put in all the validation for the key

	// TODO : create the key if not set

	lock := backend.keyLock(keyName)
	lock.RLock()
	defer lock.RUnlock()

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("keys/%s", keyName), key)
	if err != nil {
		return fmt.Errorf("Error converting key to JSON: %#v", err)
	}

	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("Error saving key: %#v", err)
	}

	return nil
}

// ValidatePublicAndPrivateKeys will return an error if the keys are not valid.
func ValidatePublicAndPrivateKeys(key *KeyStorageEntry) error {

	if key.PrivateKey == "" {
		return GeneratePublicAndPrivateKeys(key)
	}

	switch {
	case key.Algorithm[:2] == "HS":
		return nil
	case key.Algorithm[:2] == "RS" || key.Algorithm[:2] == "PS":

		privateKey, err := crypto.ParseRSAPrivateKeyFromPEM([]byte(key.PrivateKey))
		if err != nil {
			return err
		}

		key.PublicKey, err = convertPublicKeyToPEM(privateKey.PublicKey)

		if _, e := crypto.ParseRSAPublicKeyFromPEM([]byte(key.PublicKey)); e != nil {
			return e
		}
		return err
	default:
		return fmt.Errorf("unsupported algorithm: %q", key.Algorithm)
	}

}

// GeneratePublicAndPrivateKeys will set the PublicKey and PrivateKey
// fields on the key entry based on the algorithm.
func GeneratePublicAndPrivateKeys(key *KeyStorageEntry) error {

	var (
		err error
	)

	switch {
	case key.Algorithm[:2] == "HS":
		key.PrivateKey, err = generateSymmetricKey()
	case key.Algorithm[:2] == "RS" || key.Algorithm[:2] == "PS":
		key.PrivateKey, key.PublicKey, err = generateRSAKeys()
	case key.Algorithm[:2] == "ES":
		key.PrivateKey, key.PublicKey, err = generateECKeys(key.Algorithm)
	default:
		return fmt.Errorf("unrecognized algorithm: %q", key.Algorithm)
	}

	return err
}

func generateSymmetricKey() (string, error) {

	b := make([]byte, 256)
	_, err := rand.Read(b)

	return string(b), err

}

func generateRSAKeys() (private, public string, err error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	var privBuf = new(bytes.Buffer)

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	pem.Encode(privBuf, &privateKeyBlock)

	publicKey, err := convertPublicKeyToPEM(&privateKey.PublicKey)

	return privBuf.String(), publicKey, err
}

func generateECKeys(alg string) (private, public string, err error) {

	var (
		curve elliptic.Curve
	)

	switch alg {
	case "EC256":
		curve = elliptic.P256()
	case "EC384":
		curve = elliptic.P384()
	case "EC521":
		curve = elliptic.P521()
	default:
		return "", "", fmt.Errorf("unsupported algorithm: %q", alg)
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", err
	}

	var privBuf = new(bytes.Buffer)

	privateKeyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	privateKeyBlock := pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	pem.Encode(privBuf, &privateKeyBlock)

	publicKey, err := convertPublicKeyToPEM(&key.PublicKey)

	return privBuf.String(), publicKey, err
}

func convertPublicKeyToPEM(key interface{}) (string, error) {
	var pubBuf = new(bytes.Buffer)

	publicKeyDer, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	pem.Encode(pubBuf, &publicKeyBlock)
	return pubBuf.String(), nil
}
