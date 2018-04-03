# Vault JWT Secrets Plugin 

## Purpose
The purpose of this plugin is to allow vault to sign JWT tokens. This is based on the spec at https://github.com/hashicorp/vault/issues/1986, but currently only supporting JWT (not JWE and JWS as outlined in the spec).


## Tools

- `./build.sh` builds the plugin, computes the hash, and places both in the ./build folder
- `./docker.sh` builds a docker image named `vault-jose` that will mount the plugin when it starts, then starts it
- `./smoke/smoke.sh` runs a smoke test of the plugin: build, install in vault, and perform basic configuration and signing


## Installing

https://www.vaultproject.io/docs/plugin/index.html

