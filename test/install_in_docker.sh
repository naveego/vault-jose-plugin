#!/bin/sh
# wait for vault to start
until $(vault status | grep "Cluster ID" > /dev/null); do 
  >&2 echo "Vault is unavailable - sleepy time"
  sleep 1
done

>&2 echo "Vault ready - carry on"

VAULT_SECRETS_FILE=${VAULT_SECRETS_FILE:-"/opt/secrets.json"}
VAULT_APP_ID_FILE=${VAULT_APP_ID_FILE:-"/opt/app-id.json"}
VAULT_POLICIES_FILE=${VAULT_POLICIES_FILE:-"/opt/policies.json"}

# set up vault
vault login root

# enable app role auth
vault auth enable approle

# enable database plugin
vault secrets enable database

# install the jwt plugin
vault write sys/plugins/catalog/jose sha_256=$(cat /vault/plugins/jose-plugin.sha) command=jose-plugin

# enable jose plugin
vault secrets enable --plugin-name=jose --description="JWT token issuer" --path="jose" plugin

# parse JSON array, populate Vault
if [[ -f "$VAULT_SECRETS_FILE" ]]; then
  for path in $(jq -r 'keys[]' < "$VAULT_SECRETS_FILE"); do
    jq -rj ".\"${path}\"" < "$VAULT_SECRETS_FILE" > /tmp/value
    echo "writing value to ${path}"
    vault kv put "${path}" "@/tmp/value"
    rm -f /tmp/value
  done
else
  echo "$VAULT_SECRETS_FILE not found, skipping"
fi


# Optionally install the app id backend.
if [ -n "$VAULT_USE_APP_ID" ]; then
  vault auth-enable app-id
  if [[ -f "$VAULT_APP_ID_FILE" ]]; then
  	for appID in $(jq -rc '.[]' < "$VAULT_APP_ID_FILE"); do
	    name=$(echo "$appID" | jq -r ".name")
	    policy=$(echo "$appID" | jq -r ".policy")
	    echo "creating AppID policy with app ID $name for policy $policy"
	    vault write auth/app-id/map/app-id/$name value=$policy display_name=$name
      for userID in $(echo "$appID" | jq -r ".user_ids[]"); do
        name=$(echo "$appID" | jq -r ".name")
        echo "...creating user ID $userID for AppID $name"
        vault write auth/app-id/map/user-id/${userID} value=${name}
      done
  	done
  else
    echo "$VAULT_APP_ID_FILE not found, skipping"
  fi
fi

# Create any policies.
if [[ -f "$VAULT_POLICIES_FILE" ]]; then
  for policy in $(jq -r 'keys[]' < "$VAULT_POLICIES_FILE"); do
  	jq -rj ".\"${policy}\"" < "$VAULT_POLICIES_FILE" > /tmp/value
  	echo "creating vault policy $policy"
  	vault policy write "${policy}" /tmp/value
  	rm -f /tmp/value
  done
else
  echo "$VAULT_POLICIES_FILE not found, skipping"
fi
