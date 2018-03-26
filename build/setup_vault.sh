#! /bin/sh


# wait for vault to start
until $(vault status | grep "Cluster ID" > /dev/null); do 
  >&2 echo "Vault is unavailable - sleepy time"
  sleep 1
done

>&2 echo "Vault ready - carry on"

# set up vault
vault login root

# set the vault policies
vault policy write jwt jwt_policy.hcl

# install the jwt plugin
vault write sys/plugins/catalog/jwt-secrets sha_256=$(cat /vault/plugins/jwt-secrets-plugin.sha) command=jwt-secrets-plugin

vault secrets enable --plugin-name=jwt-secrets --description="JWT token issuer" --path="jwt" plugin
