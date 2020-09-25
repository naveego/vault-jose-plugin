package josejwt

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type configStorageEntry struct {
	Lease    time.Duration `json:"lease" structs:"lease" mapstructure:"lease"`
	LeaseMax time.Duration `json:"lease_max" structs:"lease_max" mapstructure:"lease_max"`
	BaseURL  string        `json:"base_url" structs:"base_url" mapstructure:"base_url"`
}

func (c *configStorageEntry) toLeaseMap() map[string]interface{} {
	return map[string]interface{}{
		"lease":     c.Lease.Seconds(),
		"lease_max": c.LeaseMax.Seconds(),
	}
}

func defaultConfig() *configStorageEntry {
	return &configStorageEntry{
		Lease:    time.Minute * 15,
		LeaseMax: time.Hour * 1,
	}
}

func getConfig(ctx context.Context, req *logical.Request) (*configStorageEntry, error) {
	entry, err := req.Storage.Get(ctx, "config")
	if err != nil {
		return defaultConfig(), err
	}
	if entry == nil {
		return defaultConfig(), nil
	}

	var config configStorageEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return defaultConfig(), err
	}

	return &config, nil
}

func writeConfig(ctx context.Context, req *logical.Request, config *configStorageEntry) error {
	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("unable to marshal entry into JSON")
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return err
	}

	return nil
}
