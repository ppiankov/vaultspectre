#!/bin/bash

# Fetch deployment token from Vault
export DEPLOY_TOKEN=$(vault read secret/data/prod/deploy/token -field=value)

# Fetch another secret
vault kv read secret/data/staging/api/credentials

echo "Deployment started"
