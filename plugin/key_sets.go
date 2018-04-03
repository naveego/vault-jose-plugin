package josejwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/vault/logical"
)

// KeySetStorageEntry strutcure defines the type of object that is stored
type KeySetStorageEntry struct {
	Name string

	ActiveKID string

	Keys map[string]jose.JSONWebKey
}

func (k *KeySetStorageEntry) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"name":       k.Name,
		"active_kid": k.ActiveKID,
	}
}

func (k *KeySetStorageEntry) AddKey(toAdd jose.JSONWebKey) error {

	if !toAdd.Valid() && toAdd.Algorithm[0:2]!="HS" {
		return errors.New("key was invalid")
	}

	if toAdd.IsPublic() {
		return errors.New("key was a public key")
	}

	if k.Keys == nil {
		k.Keys = make(map[string]jose.JSONWebKey, 1)
	}

	if _, ok := k.Keys[toAdd.KeyID]; ok {
		return errors.New("`kid` must be unique")
	}

	k.Keys[toAdd.KeyID] = toAdd

	if k.ActiveKID == "" {
		k.ActiveKID = toAdd.KeyID
	}

	return nil
}

func (k *KeySetStorageEntry) Exists(kid string) bool {
	_, ok := k.Keys[kid]
	return ok
}
func (k *KeySetStorageEntry) RemoveKey(kid string) {
	delete(k.Keys, kid)
}

func (k *KeySetStorageEntry) GetPublicKey(kid string) jose.JSONWebKey {
	if key, ok := k.Keys[kid]; ok {

		return key.Public()
	}

	return jose.JSONWebKey{}
}

func (k *KeySetStorageEntry) SetActiveKID(kid string) error {

	if _, ok := k.Keys[kid]; !ok {
		return errors.New("no key with provided `kid` was found")
	}

	k.ActiveKID = kid
	return nil
}

func (k *KeySetStorageEntry) GetActiveKey() (jose.JSONWebKey, error) {

	key, ok := k.Keys[k.ActiveKID]
	if !ok {
		return key, errors.New("no key with provided `kid` was found")
	}

	return key, nil
}

func (k *KeySetStorageEntry) PublicKeyAsMap(kid string) (m map[string]interface{}) {
	jwk, ok := k.Keys[kid]
	if !ok {
		return nil
	}

	switch jwk.Key.(type) {
	case []byte:
		return nil
	}

	j, _ := jwk.Public().MarshalJSON()
	_ = json.Unmarshal(j, &m)
	return
}

func (backend *JwtBackend) getKeySetEntry(ctx context.Context, storage logical.Storage, keyName string) (*KeySetStorageEntry, error) {
	if keyName == "" {
		return nil, fmt.Errorf("missing key name")
	}
	keyName = strings.ToLower(keyName)

	result := new(KeySetStorageEntry)
	if entry, err := storage.Get(ctx, fmt.Sprintf("keyset/%s", keyName)); err != nil {
		return nil, fmt.Errorf("error getting entry from storage: %s", err)
	} else if entry == nil || entry.Value == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(result); err != nil {
		return nil, fmt.Errorf("error decoding entry JSON: %s", err)
	}

	return result, nil
}

func (backend *JwtBackend) deleteKeySetEntry(ctx context.Context, storage logical.Storage, name string) error {
	if name == "" {
		return fmt.Errorf("missing key name")
	}
	name = strings.ToLower(name)

	err := storage.Delete(ctx, fmt.Sprintf("keyset/%s", name))
	return err
}

// Save the key entry to the local storage
func (backend *JwtBackend) setKeySetEntry(ctx context.Context, storage logical.Storage, keySet *KeySetStorageEntry) error {

	var err error

	name := strings.ToLower(keySet.Name)

	if name == "" {
		return fmt.Errorf("Unable to save key, invalid name")
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("keyset/%s", name), keySet)
	if err != nil {
		return fmt.Errorf("error converting key to JSON: %s", err)
	}

	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("error saving key: %#v", err)
	}

	return nil
}

func GenerateKey(kid, alg, use string, rsaBits, symmetricBits int) (*jose.JSONWebKey, error) {

	var (
		privKey interface{}
		err     error
	)

	symmetric := alg[:2] == "HS"

	if !strings.HasPrefix(alg, "RS") {
		rsaBits = 0
	}

	if symmetric {
		b := make([]byte, symmetricBits)
		privKey = b
		_, err = rand.Read(b)
		if err != nil {
			return nil, err
		}

	} else {
		switch use {
		case "sig":
			_, privKey, err = KeygenSig(jose.SignatureAlgorithm(alg), rsaBits)
		case "enc":
			_, privKey, err = KeygenEnc(jose.KeyAlgorithm(alg), rsaBits)
		}
	}
	if err != nil {
		return nil, err
	}

	return &jose.JSONWebKey{Key: privKey, KeyID: kid, Algorithm: alg, Use: use}, nil
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

func LoadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	return nil, fmt.Errorf("parse error, got '%s', '%s', and '%s'", err0, err1, err2)
}
