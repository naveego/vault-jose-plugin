package josejwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"golang.org/x/crypto/ed25519"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/vault/logical"
)

// KeyStorageEntry strutcure defines the type of object that is stored
type KeyStorageEntry struct {
	ID string

	// the name of the private key
	Name string

	// private key can be generated or provided based on alg type
	PrivateKey *jose.JSONWebKey

	// Public key that can be sent to third parties
	PublicKey *jose.JSONWebKey
}

type rawKeyEntry struct {
	ID             string `json:"id" structs:"id" mapstructure:"id"`
	Name           string `json:"name" structs:"name" mapstructure:"name"`
	PrivateKeyJSON []byte `json:"private_key_json" structs:"private_key_json" mapstructure:"private_key_json"`
	PublicKeyJSON  []byte `json:"public_key_json" structs:"public_key_json" mapstructure:"public_key_json"`
}

func (k *KeyStorageEntry) MarshalJSON() ([]byte, error) {
	raw := rawKeyEntry{
		ID:   k.ID,
		Name: k.Name,
	}
	var err error

	if raw.PrivateKeyJSON, err = k.PrivateKey.MarshalJSON(); err != nil {
		return nil, fmt.Errorf("error serializing private key: %s", err)
	}

	if k.PublicKey != nil && k.PublicKey.Valid() {
		if raw.PublicKeyJSON, err = k.PublicKey.MarshalJSON(); err != nil {
			return nil, fmt.Errorf("error serializing public key: %s", err)
		}
	}

	return json.Marshal(raw)
}

func (k *KeyStorageEntry) UnmarshalJSON(b []byte) error {
	var raw rawKeyEntry
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	k.ID = raw.ID
	k.Name = raw.Name

	k.PrivateKey = new(jose.JSONWebKey)
	k.PublicKey = new(jose.JSONWebKey)

	if err := k.PrivateKey.UnmarshalJSON(raw.PrivateKeyJSON); err != nil {
		return err
	}

	if raw.PublicKeyJSON != nil {

		if err := k.PublicKey.UnmarshalJSON(raw.PublicKeyJSON); err != nil {
			return err
		}
	}

	return nil
}

func (backend *JwtBackend) getKeyEntry(ctx context.Context, storage logical.Storage, keyName string) (*KeyStorageEntry, error) {
	if keyName == "" {
		return nil, fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	result := new(KeyStorageEntry)
	if entry, err := storage.Get(ctx, fmt.Sprintf("keys/%s", keyName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := result.UnmarshalJSON(entry.Value); err != nil {
		return nil, err
	}

	return result, nil
}

func (backend *JwtBackend) deleteKeyEntry(ctx context.Context, storage logical.Storage, keyName string) error {
	if keyName == "" {
		return fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	err := storage.Delete(ctx, fmt.Sprintf("keys/%s", keyName))
	return err
}

// Save the key entry to the local storage
func (backend *JwtBackend) setKeyEntry(ctx context.Context, storage logical.Storage, key KeyStorageEntry) error {

	var err error

	if key.Name == "" {
		return fmt.Errorf("Unable to save key, invalid name")
	}

	keyName := strings.ToLower(key.Name)

	entry := &logical.StorageEntry{
		Key: fmt.Sprintf("keys/%s", keyName),
	}

	entry.Value, err = key.MarshalJSON()
	if err != nil {
		return fmt.Errorf("error converting key to JSON: %s", err)
	}

	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("error saving key: %#v", err)
	}

	return nil
}

// GeneratePublicAndPrivateKeys will set the PublicKey and PrivateKey
// fields on the key entry based on the algorithm.
func GeneratePublicAndPrivateKeys(key *KeyStorageEntry, alg, use string) error {

	key.ID = uuid.New().String()

	if alg[:2] == "HS" {
		b := make([]byte, 256)
		_, err := rand.Read(b)
		key.PrivateKey = &jose.JSONWebKey{Key: b, KeyID: key.ID, Algorithm: alg, Use: use}
		return err
	}

	var privKey crypto.PublicKey
	var pubKey crypto.PrivateKey
	var err error
	switch use {
	case "sig":
		pubKey, privKey, err = KeygenSig(jose.SignatureAlgorithm(alg), 2048)
	case "enc":
		pubKey, privKey, err = KeygenEnc(jose.KeyAlgorithm(alg), 2048)
	}

	if err != nil {
		return err
	}

	key.PrivateKey = &jose.JSONWebKey{Key: privKey, KeyID: key.ID, Algorithm: alg, Use: use}
	key.PublicKey = &jose.JSONWebKey{Key: pubKey, KeyID: key.ID, Algorithm: alg, Use: use}

	if key.PrivateKey.IsPublic() || !key.PublicKey.IsPublic() || !key.PrivateKey.Valid() || !key.PublicKey.Valid() {
		return errors.New("invalid keys were generated")
	}

	return nil
}

// KeygenSig generates keypair for corresponding SignatureAlgorithm.
func KeygenSig(alg jose.SignatureAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		keylen := map[jose.SignatureAlgorithm]int{
			jose.ES256: 256,
			jose.ES384: 384,
			jose.ES512: 521, // sic!
			jose.EdDSA: 256,
		}
		if bits != 0 && bits != keylen[alg] {
			return nil, nil, errors.New("this `alg` does not support arbitrary key length")
		}
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
	}
	switch alg {
	case jose.ES256:
		// The cryptographic operations are implemented using constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key.Public(), key, err
	case jose.ES384:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return key.Public(), key, err
	case jose.ES512:
		// NB: The cryptographic operations do not use constant-time algorithms.
		key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return key.Public(), key, err
	case jose.EdDSA:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		return pub, key, err
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `sig`")
	}
}

// KeygenEnc generates keypair for corresponding KeyAlgorithm.
func KeygenEnc(alg jose.KeyAlgorithm, bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch alg {
	case jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256:
		if bits == 0 {
			bits = 2048
		}
		if bits < 2048 {
			return nil, nil, errors.New("too short key for RSA `alg`, 2048+ is required")
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		return key.Public(), key, err
	case jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW:
		var crv elliptic.Curve
		switch bits {
		case 0, 256:
			crv = elliptic.P256()
		case 384:
			crv = elliptic.P384()
		case 521:
			crv = elliptic.P521()
		default:
			return nil, nil, errors.New("unknown elliptic curve bit length, use one of 256, 384, 521")
		}
		key, err := ecdsa.GenerateKey(crv, rand.Reader)
		return key.Public(), key, err
	default:
		return nil, nil, errors.New("unknown `alg` for `use` = `enc`")
	}
}
