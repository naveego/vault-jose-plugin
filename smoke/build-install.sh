#!/bin/sh

CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build  -ldflags "-s" -a -installsuffix cgo -o ./bin/jose-plugin github.com/naveego/vault-jose-plugin
shasum -a 256 -p bin/jose-plugin | cut -d ' ' -f 1 > "./bin/jose-plugin.sha"

export VAULT_ADDR=http://127.0.0.1:8200

vault write sys/plugins/catalog/jose sha_256=$(cat bin/jose-plugin.sha) command=jose-plugin

vault secrets enable --plugin-name=jose --description="JWT token issuer" --path="jose" plugin
