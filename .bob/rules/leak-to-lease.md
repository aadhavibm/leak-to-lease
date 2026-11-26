- Never read, print, echo or log a secret value. Refer to secrets
  only by file path, line number and SHA-256 fingerprint.
- Never open credential files with read_file. To find them, use
  commands that output paths and line numbers only.
- Never commit tokens, .env files or Vault data.
- Ask before any command that changes Vault or MySQL.
- Work in small steps. After each change, run tests and show output.
- Use only public docs (developer.hashicorp.com, spring.io).
