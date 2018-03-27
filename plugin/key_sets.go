package josejwt

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

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

// AddGeneratedKey generates a new key and adds it.
func (k *KeySetStorageEntry) AddGeneratedKey(kid, alg, use string, rsaBits, symmetricBits int) error {

	var (
		key     jose.JSONWebKey
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
			return err
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
		return err
	}

	key = jose.JSONWebKey{Key: privKey, KeyID: kid, Algorithm: alg, Use: use}

	if !symmetric {
		if key.IsPublic() || !key.Valid() {
			return errors.New("invalid key was generated")
		}
	}
	return k.AddKey(key)
}

func (k *KeySetStorageEntry) AddKey(toAdd jose.JSONWebKey) error {

	if _, ok := k.Keys[toAdd.KeyID]; ok {
		return errors.New("`kid` must be unique")
	}

	k.Keys[toAdd.KeyID] = toAdd

	return nil
}

func (k *KeySetStorageEntry) RemoveKey(kid string) {
	delete(k.Keys, kid)
}

func (k *KeySetStorageEntry) GetPublicKey(kid string) interface{} {
	if key, ok := k.Keys[kid]; ok {

		switch key.Key.(type) {
		case []byte:
			return nil
		default:
			return key
		}
	}

	return nil
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
