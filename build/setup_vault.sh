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
vault write sys/plugins/catalog/jose sha_256=$(cat jose-plugin.sha) command=jose-plugin

vault secrets enable --plugin-name=jose --description="JWT token issuer" --path="jose" plugin
