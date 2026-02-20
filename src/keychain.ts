import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// ── Types ──────────────────────────────────────────────────────

export type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export interface SiloConfig {
  /** Keychain service name — groups all your app's secrets. */
  service: string;
  /**
   * Determines whether an account should be routed to the
   * locked keychain. Defaults to `account.includes('production')`.
   */
  isProtected?: (account: string) => boolean;
}

// ── Internal helpers ───────────────────────────────────────────

function keychainPath(service: string): string {
  return join(
    homedir(),
    `Library/Keychains/${service}-protected.keychain-db`,
  );
}

function defaultIsProtected(account: string): boolean {
  return account.includes('production');
}

function lock(path: string): void {
  try {
    execFileSync(
      '/usr/bin/security',
      ['lock-keychain', path],
      { stdio: 'pipe' },
    );
  } catch {
    // Best-effort lock
  }
}

// ── Public API ─────────────────────────────────────────────────

export function isKeychainSetup(config: SiloConfig): boolean {
  return existsSync(keychainPath(config.service));
}

export function createKeychain(
  config: SiloConfig,
): Result<void> {
  const path = keychainPath(config.service);

  if (existsSync(path)) {
    return { ok: true, value: undefined };
  }

  try {
    // stdio: 'inherit' — user types password directly in terminal
    execFileSync(
      '/usr/bin/security',
      ['create-keychain', path],
      { stdio: 'inherit' },
    );

    // Keychain is left unlocked so the caller can store
    // credentials immediately. Call activateKeychain()
    // after the initial store to enable auto-lock.
    return { ok: true, value: undefined };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: `Failed to create keychain: ${msg}`,
    };
  }
}

/**
 * Unlock the keychain via terminal prompt.
 *
 * Chains unlock + set-keychain-settings in a single shell
 * command so there's no gap for the keychain to re-lock
 * between calls. One terminal prompt, then the timeout
 * change happens in the same session.
 */
export function unlockKeychain(config: SiloConfig): Result<void> {
  const path = keychainPath(config.service);

  try {
    execFileSync('/bin/sh', [
      '-c',
      `security unlock-keychain "${path}"` +
        ` && security set-keychain-settings -t 10 -l "${path}"`,
    ], { stdio: 'inherit' });
    return { ok: true, value: undefined };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      error: `Failed to unlock keychain: ${msg}`,
    };
  }
}

/**
 * Enable auto-lock settings and lock the keychain.
 * Call this AFTER the initial credential store so the
 * keychain is unlocked during the first write.
 */
export function activateKeychain(config: SiloConfig): void {
  const path = keychainPath(config.service);
  try {
    // timeout=10: grace period between unlock and operation
    // -l: lock on sleep
    execFileSync(
      '/usr/bin/security',
      ['set-keychain-settings', '-t', '10', '-l', path],
      { stdio: 'pipe' },
    );
  } catch {
    // Settings may fail if keychain already locked — not fatal
  }
  lock(path);
}

export function store(
  config: SiloConfig,
  account: string,
  value: string,
): Result<void> {
  const isProtected = (config.isProtected ?? defaultIsProtected);
  const protect = isProtected(account);
  const path = keychainPath(config.service);

  try {
    if (protect) {
      const unlock = unlockKeychain(config);
      if (!unlock.ok) return unlock;

      execFileSync('/usr/bin/security', [
        'add-generic-password',
        '-s', config.service,
        '-a', account,
        '-w', value,
        '-U',
        path,
      ], { stdio: 'pipe' });
      lock(path);
    } else {
      execFileSync('/usr/bin/security', [
        'add-generic-password',
        '-s', config.service,
        '-a', account,
        '-w', value,
        '-U',
      ], { stdio: 'pipe' });
    }

    return { ok: true, value: undefined };
  } catch (err) {
    if (protect) lock(path);
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, error: `Failed to store secret: ${msg}` };
  }
}

export function get(
  config: SiloConfig,
  account: string,
): Result<string> {
  const isProtected = (config.isProtected ?? defaultIsProtected);
  const protect = isProtected(account);
  const path = keychainPath(config.service);

  try {
    let result: string;

    if (protect) {
      const unlock = unlockKeychain(config);
      if (!unlock.ok) {
        return { ok: false, error: unlock.error };
      }

      result = execFileSync('/usr/bin/security', [
        'find-generic-password',
        '-s', config.service,
        '-a', account,
        '-w',
        path,
      ], { stdio: 'pipe', encoding: 'utf-8' });
      lock(path);
    } else {
      result = execFileSync('/usr/bin/security', [
        'find-generic-password',
        '-s', config.service,
        '-a', account,
        '-w',
      ], { stdio: 'pipe', encoding: 'utf-8' });
    }

    return { ok: true, value: result.trim() };
  } catch (err) {
    if (protect) lock(path);
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('could not be found')) {
      return {
        ok: false,
        error: `No secret found for "${account}"`,
      };
    }
    return { ok: false, error: `Keychain read failed: ${msg}` };
  }
}

export function remove(
  config: SiloConfig,
  account: string,
): Result<void> {
  const isProtected = (config.isProtected ?? defaultIsProtected);
  const protect = isProtected(account);
  const path = keychainPath(config.service);

  try {
    if (protect) {
      const unlock = unlockKeychain(config);
      if (!unlock.ok) return unlock;

      execFileSync('/usr/bin/security', [
        'delete-generic-password',
        '-s', config.service,
        '-a', account,
        path,
      ], { stdio: 'pipe' });
      lock(path);
    } else {
      execFileSync('/usr/bin/security', [
        'delete-generic-password',
        '-s', config.service,
        '-a', account,
      ], { stdio: 'pipe' });
    }

    return { ok: true, value: undefined };
  } catch (err) {
    if (protect) lock(path);
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('could not be found')) {
      return {
        ok: false,
        error: `No secret found for "${account}"`,
      };
    }
    return { ok: false, error: `Failed to delete secret: ${msg}` };
  }
}
