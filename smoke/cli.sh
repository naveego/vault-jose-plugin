#!/bin/sh

export VAULT_TOKEN=root VAULT_ADDR=http://127.0.0.1:8200

vault write jose/jwks/default/key1 alg=RS256 use=sig

vault write jose/roles/basic-role @jwt-role.json

vault write jose/jwt/issue/basic-role @token-with-claims.json