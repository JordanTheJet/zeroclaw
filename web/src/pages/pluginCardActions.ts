import type { PluginCatalogEntry } from '@/lib/api';

const KIND_LABEL_KEYS: Readonly<Record<string, string>> = Object.freeze({
  channel: 'plugins.kind.channel',
  tool: 'plugins.kind.tool',
  memory: 'plugins.kind.memory',
  observer: 'plugins.kind.observer',
  skill: 'plugins.kind.skill',
});

export interface PluginCardActions {
  configHref: string | null;
  /** Registry package identity displayed as data, never a shell command. */
  installSource: string | null;
  registryOrigin: PluginCatalogEntry['registry_origin'];
  primary: 'install' | 'configure' | 'none';
}

export type PluginCardStatus =
  | 'conflict'
  | 'installable'
  | 'configured_unavailable'
  | 'installed_off'
  | 'configured'
  | 'installed'
  | 'not_configured';

export function catalogKindLabelKey(kind: string): string | null {
  return Object.prototype.hasOwnProperty.call(KIND_LABEL_KEYS, kind)
    ? (KIND_LABEL_KEYS[kind] ?? null)
    : null;
}

export function groupCatalogEntries(
  entries: readonly PluginCatalogEntry[],
): Map<string, PluginCatalogEntry[]> {
  const groups = new Map<string, PluginCatalogEntry[]>();
  for (const entry of entries) {
    const group = groups.get(entry.kind);
    if (group) {
      group.push(entry);
    } else {
      groups.set(entry.kind, [entry]);
    }
  }
  return groups;
}

/** A configured channel whose provider is absent from this binary/catalog. */
export function isConfiguredProviderUnavailable(entry: PluginCatalogEntry): boolean {
  return (
    entry.kind === 'channel' &&
    entry.configured &&
    !entry.compiled_in &&
    !entry.installed &&
    !entry.available
  );
}

/** Resolve status from catalog precedence and canonical configuration intent. */
export function pluginCardStatus(
  entry: PluginCatalogEntry,
  pluginsEnabled: boolean,
): PluginCardStatus {
  if (entry.conflicted) return 'conflict';
  if (isConfiguredProviderUnavailable(entry)) return 'configured_unavailable';
  if (entry.origin === 'registry' && !entry.installed) return 'installable';
  if (entry.origin === 'plugin' && entry.installed && !pluginsEnabled) {
    return 'installed_off';
  }
  if (entry.configured) return 'configured';
  if (entry.installed) return 'installed';
  return 'not_configured';
}

/** Derive card actions solely from the gateway's canonical catalog fields. */
export function pluginCardActions(entry: PluginCatalogEntry): PluginCardActions {
  const configHref =
    entry.kind === 'channel' && entry.toggleable
      ? `/config/channels/${encodeURIComponent(entry.id)}`
      : null;
  const installSource =
    entry.available &&
    !entry.installed &&
    !entry.conflicted &&
    entry.install_source
      ? entry.install_source
      : null;

  return {
    configHref,
    installSource,
    registryOrigin: installSource ? entry.registry_origin : null,
    primary: installSource ? 'install' : configHref ? 'configure' : 'none',
  };
}
