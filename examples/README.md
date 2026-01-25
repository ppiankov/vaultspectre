# VaultSpectre Examples

## Test Repository

The `test-repo/` directory contains sample files with Vault secret references for testing VaultSpectre.

### Running the Scanner

Without Vault connection (scan only):
```bash
# This will fail because Vault connection is required, but shows the scanner finds references
../bin/vaultspectre scan --repo ./test-repo --vault-addr http://localhost:8200 --token dummy
```

### Expected References

The scanner should find the following secret paths:

1. `secret/data/prod/database/password` (ansible/playbook.yml)
2. `secret/data/prod/api/key` (ansible/playbook.yml)
3. `secret/data/prod/missing/secret` (ansible/playbook.yml)
4. `secret/data/prod/deploy/token` (scripts/deploy.sh)
5. `secret/data/staging/api/credentials` (scripts/deploy.sh)
6. `secret/data/prod/database/credentials` (config/application.yml)
7. `secret/data/prod/api/token` (config/application.yml)
8. `secret/data/prod/redis/password` (config/application.yml)

### Testing with Real Vault

To test with a real Vault instance:

1. Start Vault in dev mode:
   ```bash
   vault server -dev
   ```

2. Create some test secrets:
   ```bash
   export VAULT_ADDR='http://127.0.0.1:8200'
   export VAULT_TOKEN='root'

   vault kv put secret/prod/database/password value=secret123
   vault kv put secret/prod/api/key value=apikey456
   vault kv put secret/prod/deploy/token value=token789
   ```

3. Run VaultSpectre:
   ```bash
   cd examples
   ../bin/vaultspectre scan \
     --repo ./test-repo \
     --vault-addr $VAULT_ADDR \
     --token $VAULT_TOKEN
   ```

This will show which secrets exist and which are missing.
