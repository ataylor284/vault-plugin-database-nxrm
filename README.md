Vault Database Plugin for Sonatype Nexus Repository Manager
===========================================================

This plugin allows hashicorp vault to create temporary credentials for use with Nexus Repository Manager.

Building
--------

    go build -o vault-plugin-database-nxrm cmd/vault-plugin-database-nxrm/main.go

Configuration
-------------

    vault secrets enable database

    vault write database/roles/nxrm-vault db_name=nxrm creation_statements='{"nxrm-roles": ["nx-admin"]}' default_ttl="1h" max_ttl="24h"

    vault write database/config/nxrm plugin_name="vault-plugin-database-nxrm" allowed_roles="nxrm-vault" username=admin password=admin123 url=http://localhost:8081

