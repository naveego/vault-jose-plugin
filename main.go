package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	sdk "github.com/hashicorp/vault/sdk/plugin"
	"github.com/naveego/vault-jose-plugin/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:]) // Ignore command, strictly parse flags

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	factoryFunc := josejwt.Factory

	err := sdk.Serve(&sdk.ServeOpts{
		BackendFactoryFunc: factoryFunc,
		TLSProviderFunc:    tlsProviderFunc,
	})
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
