# @dean0x/silo

OS-enforced secret protection for macOS. Prevents AI coding agents from silently accessing your production credentials.

## The Problem

Your coding agent has terminal access. It can run:

```bash
security find-generic-password -s "my-app" -a "db-production" -w
```

If your secrets are in the default macOS Keychain (unlocked since login), there's no prompt. No dialog. No trace. Prompt injection can trick agents into doing exactly this.

## The Fix

Silo stores production secrets in a **separate locked keychain** that requires a password prompt for every access. When locked, macOS shows a system-level password dialog that no code, no agent, and no prompt injection can bypass.

```
Agent tries to read → keychain is locked → macOS password dialog → human decides
```

## Install

```bash
npm install @dean0x/silo
```

## CLI Usage

```bash
# Create a locked keychain for your app
silo init my-app

# Store a production secret (auto-locks after)
silo store my-app db-production "postgresql://prod:secret@host/db"

# Retrieve it (macOS password dialog appears)
silo get my-app db-production

# Store a staging secret (no prompt — uses login keychain)
silo store my-app db-staging "postgresql://staging:pass@host/db"

# Retrieve staging (no prompt)
silo get my-app db-staging

# Delete a secret
silo remove my-app db-production

# Check keychain status
silo status my-app
```

Accounts containing `"production"` are automatically routed to the locked keychain. Everything else uses the default login keychain with zero friction.

## SDK Usage

```typescript
import { createKeychain, store, get, remove } from '@dean0x/silo';
import type { SiloConfig } from '@dean0x/silo';

const config: SiloConfig = { service: 'my-app' };

// One-time setup (user sets a keychain password)
createKeychain(config);

// Store a production credential (locks after)
store(config, 'db-production', connectionString);

// Read it back (macOS password dialog appears, locks after)
const result = get(config, 'db-production');
if (result.ok) {
  connectToDatabase(result.value);
}

// Staging — no prompt
store(config, 'db-staging', stagingString);
const staging = get(config, 'db-staging'); // silent
```

## Custom Protection Rules

By default, any account containing `"production"` is protected. Override this:

```typescript
const config: SiloConfig = {
  service: 'my-app',
  isProtected: (account) =>
    account.startsWith('prod-') || account.startsWith('live-'),
};
```

## How It Works

1. `silo init` creates a separate macOS keychain at `~/Library/Keychains/<service>-protected.keychain-db`
2. The keychain is configured with timeout=0 (lock immediately when idle) and lock-on-sleep
3. Every `get`, `store`, and `remove` operation on protected accounts **explicitly locks the keychain after completing**
4. When locked, macOS requires the keychain password via a system dialog — no code can bypass this

## Why This Stops Prompt Injection

| Without Silo | With Silo |
|---|---|
| Agent runs `security find-generic-password -w` | Agent runs the same command |
| Secret returned silently | macOS shows password dialog |
| Agent has the secret | Agent can't type the password |
| Exfiltration possible | **Attack blocked at OS level** |

## Limitations

- **macOS only** — uses the macOS Security framework
- **Not for cloud secrets** — use AWS Secrets Manager, Vault, etc. for server-side
- **Doesn't prevent authorized exfiltration** — if you type the password, the agent gets the secret for that session

## Requirements

- macOS
- Node.js >= 18

## License

MIT
