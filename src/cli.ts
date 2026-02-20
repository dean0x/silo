#!/usr/bin/env node

import {
  createKeychain,
  activateKeychain,
  unlockKeychain,
  store,
  get,
  remove,
  isKeychainSetup,
} from './keychain.js';
import type { SiloConfig } from './keychain.js';

const USAGE = `
silo — OS-enforced secret protection for macOS

Usage:
  silo init <service>                    Create a locked keychain for a service
  silo store <service> <account> <value> Store a secret
  silo get <service> <account>           Retrieve a secret (prompts if protected)
  silo remove <service> <account>        Delete a secret
  silo status <service>                  Check if keychain is configured

Examples:
  silo init my-app
  silo store my-app db-production "postgresql://..."
  silo get my-app db-production
  silo store my-app db-staging "postgresql://..."
  silo get my-app db-staging

Accounts containing "production" are automatically routed to the
locked keychain and require a password prompt on every access.
All other accounts use the default login keychain (no prompt).
`.trim();

function fail(msg: string): never {
  console.error(`❌ ${msg}`);
  return process.exit(1);
}

function main(): void {
  const [command, ...rest] = process.argv.slice(2);

  if (!command || command === '--help' || command === '-h') {
    console.log(USAGE);
    process.exit(0);
  }

  switch (command) {
    case 'init': {
      const [service] = rest;
      if (!service) fail('Usage: silo init <service>');

      const config: SiloConfig = { service };

      if (isKeychainSetup(config)) {
        console.log(
          `✅ Keychain already configured for "${service}"`,
        );
        return;
      }

      console.log(
        `🔒 Creating locked keychain for "${service}"...`,
      );
      const result = createKeychain(config);
      if (!result.ok) fail(result.error);
      activateKeychain(config);
      console.log(
        '✅ Keychain created (locks after every use)',
      );
      break;
    }

    case 'store': {
      const [service, account, value] = rest;
      if (!service || !account || !value) {
        fail('Usage: silo store <service> <account> <value>');
      }

      const config: SiloConfig = { service };
      const isProtected = account.includes('production');
      const alreadyExists = isKeychainSetup(config);
      const freshKeychain = isProtected && !alreadyExists;

      if (isProtected) {
        if (!alreadyExists) {
          // First time — create keychain (stays unlocked for store)
          console.log(
            `🔒 Creating locked keychain for "${service}"...`,
          );
          const kc = createKeychain(config);
          if (!kc.ok) fail(kc.error);
          console.log('✅ Keychain created');
        } else {
          // Re-import — unlock via terminal prompt
          const unlock = unlockKeychain(config);
          if (!unlock.ok) fail(unlock.error);
        }
      }

      const result = store(config, account, value);
      if (!result.ok) fail(result.error);

      // Activate auto-lock after the first store
      if (freshKeychain) {
        activateKeychain(config);
      }

      console.log(`✅ Stored "${account}" in ${service}`);
      break;
    }

    case 'get': {
      const [service, account] = rest;
      if (!service || !account) {
        fail('Usage: silo get <service> <account>');
      }

      const config: SiloConfig = { service };
      const result = get(config, account);
      if (!result.ok) fail(result.error);

      // Print raw value to stdout for piping
      process.stdout.write(result.value);
      break;
    }

    case 'remove': {
      const [service, account] = rest;
      if (!service || !account) {
        fail('Usage: silo remove <service> <account>');
      }

      const config: SiloConfig = { service };
      const result = remove(config, account);
      if (!result.ok) fail(result.error);
      console.log(`✅ Removed "${account}" from ${service}`);
      break;
    }

    case 'status': {
      const [service] = rest;
      if (!service) fail('Usage: silo status <service>');

      const config: SiloConfig = { service };
      if (isKeychainSetup(config)) {
        console.log(
          `🔒 "${service}" — locked keychain configured`,
        );
      } else {
        console.log(
          `⚠️  "${service}" — no locked keychain found`,
        );
        console.log(`   Run: silo init ${service}`);
      }
      break;
    }

    default:
      fail(`Unknown command: ${command}\n\n${USAGE}`);
  }
}

main();
