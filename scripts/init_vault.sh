#!/bin/bash

export VAULT_ADDR='http://127.0.0.1:8200';

vault auth enable approle;

vault write auth/approle/role/dagu_rtcti policies=./scripts/vault_policy;

vault policy write dagu_rtcti_policy - < ./scripts/vault_policy.hcl;

vault read auth/approle/role/dagu_rtcti/role-id;

vault write -f auth/approle/role/dagu_rtcti/secret-id;

vault secrets enable -path=encryption -version=2 kv;

vault kv put encryption/jwt \
  encryption_key=$(openssl rand -hex 64) \
  encryption_iv=$(openssl rand -hex 16) \
  jwt_access_secret=$(openssl rand -hex 64) \
  jwt_refresh_secret=$(openssl rand -hex 64) \
  jwt_access_expires_in='15m' \
  jwt_refresh_expires_in='3d' \
