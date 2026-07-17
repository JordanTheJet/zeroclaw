import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  Check,
  Circle,
  Download,
  Puzzle,
  TriangleAlert,
} from 'lucide-react';
import { getPlugins } from '@/lib/api';
import type { PluginCatalogEntry, PluginCatalogIssue } from '@/lib/api';
import { t } from '@/lib/i18n';
import { Badge, Card, PageHeader } from '@/components/ui';
import type { BadgeTone } from '@/components/ui';
import {
  catalogKindLabelKey,
  groupCatalogEntries,
  isConfiguredProviderUnavailable,
  pluginCardActions,
  pluginCardStatus,
} from './pluginCardActions';

function kindLabel(kind: string): string {
  const key = catalogKindLabelKey(kind);
  return key ? t(key) : kind;
}

function sourceLabel(entry: PluginCatalogEntry): string {
  if (isConfiguredProviderUnavailable(entry)) {
    return t('plugins.source.unavailable');
  }
  if (entry.origin === 'built_in') {
    return t(entry.installed ? 'plugins.source.builtin_plugin' : 'plugins.source.builtin');
  }
  if (entry.origin === 'plugin') {
    return t(entry.mirrors_builtin ? 'plugins.source.plugin_mirror' : 'plugins.source.plugin');
  }
  return t('plugins.source.registry');
}

function statusBadge(
  entry: PluginCatalogEntry,
  pluginsEnabled: boolean,
): { label: string; tone: BadgeTone; icon: typeof Check } {
  switch (pluginCardStatus(entry, pluginsEnabled)) {
    case 'conflict':
      return { label: t('plugins.status.conflict'), tone: 'warn', icon: TriangleAlert };
    case 'configured_unavailable':
      return {
        label: t('plugins.status.configured_unavailable'),
        tone: 'warn',
        icon: TriangleAlert,
      };
    case 'installable':
      return { label: t('plugins.status.installable'), tone: 'neutral', icon: Download };
    case 'installed_off':
      return { label: t('plugins.status.installed_off'), tone: 'neutral', icon: Circle };
    case 'configured':
      return { label: t('plugins.status.configured'), tone: 'ok', icon: Check };
    case 'installed':
      return { label: t('plugins.status.installed'), tone: 'neutral', icon: Check };
    case 'not_configured':
      return { label: t('plugins.status.not_configured'), tone: 'neutral', icon: Circle };
  }
}

function issueLabel(issue: PluginCatalogIssue): string {
  if (issue.source === 'installed' && issue.code === 'discovery_failed') {
    return t('plugins.issue.discovery_failed');
  }
  if (issue.source === 'registry' && issue.code === 'cache_read_failed') {
    return t('plugins.issue.registry_cache_failed');
  }
  return t('plugins.issue.unknown');
}

function interpolate(key: string, value: string): string {
  return t(key).replace('{name}', value);
}

export default function Plugins() {
  const [entries, setEntries] = useState<PluginCatalogEntry[]>([]);
  const [issues, setIssues] = useState<PluginCatalogIssue[]>([]);
  const [pluginsEnabled, setPluginsEnabled] = useState(false);
  const [wasmPluginsAvailable, setWasmPluginsAvailable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeKind, setActiveKind] = useState<string>('all');
  const [reload, setReload] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    getPlugins()
      .then((response) => {
        if (cancelled) return;
        setEntries(response.capabilities);
        setIssues(response.issues);
        setPluginsEnabled(response.plugins_enabled);
        setWasmPluginsAvailable(response.wasm_plugins_available);
      })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : String(reason));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [reload]);

  const kinds = ['all', ...Array.from(new Set(entries.map((entry) => entry.kind))).sort()];
  const filtered =
    activeKind === 'all' ? entries : entries.filter((entry) => entry.kind === activeKind);
  const grouped = groupCatalogEntries(filtered);

  if (error) {
    return (
      <div className="p-6">
        <div
          role="alert"
          className="space-y-3 rounded-[var(--radius-md)] border border-status-error/25 bg-status-error/10 p-4 text-sm text-status-error"
        >
          <p>{t('plugins.load_error')}: {error}</p>
          <button
            type="button"
            onClick={() => setReload((value) => value + 1)}
            className="rounded-[var(--radius-sm)] border border-current px-3 py-1.5 font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--pc-focus)]"
          >
            {t('common.retry')}
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="flex h-64 items-center justify-center gap-3 text-sm text-pc-text-muted"
      >
        <span
          aria-hidden="true"
          className="h-8 w-8 animate-spin rounded-full border-2 border-pc-border"
          style={{ borderTopColor: 'var(--pc-accent)' }}
        />
        <span>{t('plugins.loading')}</span>
      </div>
    );
  }

  const systemStatus = !wasmPluginsAvailable
    ? t('plugins.system_unavailable')
    : pluginsEnabled
      ? t('plugins.system_on')
      : t('plugins.system_off');

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title={t('plugins.title')}
        description={t('plugins.subtitle')}
        actions={<Badge tone={wasmPluginsAvailable && pluginsEnabled ? 'ok' : 'neutral'}>
          {systemStatus}
        </Badge>}
      />

      {!wasmPluginsAvailable && (
        <div
          role="status"
          className="rounded-[var(--radius-md)] border border-pc-border bg-pc-surface p-4 text-sm text-pc-text-muted"
        >
          {t('plugins.wasm_unavailable_hint')}
        </div>
      )}

      {issues.length > 0 && (
        <div
          role="alert"
          className="rounded-[var(--radius-md)] border border-status-warning/25 bg-status-warning/10 p-4 text-sm text-pc-text"
        >
          <div className="mb-2 flex items-center gap-2 font-medium">
            <TriangleAlert aria-hidden="true" className="h-4 w-4 text-status-warning" />
            {t('plugins.partial_title')}
          </div>
          <ul className="list-disc space-y-1 pl-5 text-pc-text-muted">
            {issues.map((issue) => (
              <li key={`${issue.source}:${issue.code}`}>{issueLabel(issue)}</li>
            ))}
          </ul>
        </div>
      )}

      <div
        className="flex flex-wrap gap-2"
        role="group"
        aria-label={t('plugins.filter_label')}
      >
        {kinds.map((kind) => {
          const active = activeKind === kind;
          return (
            <button
              key={kind}
              type="button"
              aria-pressed={active}
              onClick={() => setActiveKind(kind)}
              className={[
                'inline-flex h-7 cursor-pointer items-center rounded-[var(--radius-md)] border px-3 text-[13px] font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--pc-focus)]',
                active
                  ? 'border-transparent bg-pc-accent text-[#0b1220]'
                  : 'border-pc-border bg-transparent text-pc-text-secondary hover:border-pc-border-strong hover:bg-[var(--pc-hover)] hover:text-pc-text',
              ].join(' ')}
            >
              {kind === 'all' ? t('plugins.kind.all') : kindLabel(kind)}
            </button>
          );
        })}
      </div>

      {grouped.size === 0 ? (
        <Card className="p-10 text-center">
          <Puzzle aria-hidden="true" className="mx-auto mb-3 h-10 w-10 text-pc-text-faint" />
          <p className="text-sm text-pc-text-muted">{t('plugins.empty')}</p>
        </Card>
      ) : (
        Array.from(grouped.entries())
          .sort(([left], [right]) => left.localeCompare(right))
          .map(([kind, items], groupIndex) => {
            const headingId = `plugin-kind-${groupIndex}`;
            return (
              <section key={kind} aria-labelledby={headingId}>
                <h2
                  id={headingId}
                  className="mb-3 text-[11px] font-medium uppercase tracking-wider text-pc-text-faint"
                >
                  {kindLabel(kind)}
                </h2>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {items.map((entry) => {
                    const badge = statusBadge(entry, pluginsEnabled);
                    const BadgeIcon = badge.icon;
                    const actions = pluginCardActions(entry);
                    const href = actions.configHref;
                    const installSource = actions.installSource;
                    const cardHref = actions.primary === 'configure' ? href : null;
                    const title = entry.display_name ?? entry.id;
                    const body = (
                      <>
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <h3 className="truncate text-sm font-medium text-pc-text">
                              {title}
                              {entry.version && (
                                <span className="font-normal text-pc-text-faint"> v{entry.version}</span>
                              )}
                            </h3>
                            <p className="mt-1 line-clamp-2 text-sm text-pc-text-muted">
                              {entry.description ?? sourceLabel(entry)}
                            </p>
                          </div>
                          <Badge tone={badge.tone} className="flex-shrink-0">
                            <BadgeIcon aria-hidden="true" className="h-3 w-3" />
                            {badge.label}
                          </Badge>
                        </div>
                        <div className="flex items-center justify-between gap-2">
                          <Badge tone="neutral">{sourceLabel(entry)}</Badge>
                          {installSource ? (
                            <span className="flex min-w-0 items-center justify-end gap-2">
                              <span className="min-w-0 text-right text-[11px] text-pc-text-faint">
                                {t(actions.registryOrigin === 'custom'
                                  ? 'plugins.install_source.custom'
                                  : 'plugins.install_source.default')}
                                {': '}
                                <code className="break-all">{installSource}</code>
                              </span>
                              {href && (
                                <Link
                                  to={href}
                                  aria-label={interpolate('plugins.configure_aria', title)}
                                  className="flex flex-shrink-0 items-center gap-1 text-[13px] font-medium text-pc-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--pc-focus)]"
                                >
                                  {t('plugins.configure')}
                                  <ArrowRight aria-hidden="true" className="h-3.5 w-3.5" />
                                </Link>
                              )}
                            </span>
                          ) : href ? (
                            <span className="flex items-center gap-1 text-[13px] font-medium text-pc-accent">
                              {t('plugins.configure')}
                              <ArrowRight
                                aria-hidden="true"
                                className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5"
                              />
                            </span>
                          ) : null}
                        </div>
                      </>
                    );
                    return cardHref ? (
                      <Link
                        key={`${kind}:${entry.id}`}
                        to={cardHref}
                        aria-label={interpolate('plugins.configure_aria', title)}
                        className={[
                          'group flex w-full flex-col gap-3 rounded-[var(--radius-lg)] border border-pc-border bg-pc-surface p-5 text-left',
                          'transition-colors hover:border-pc-border-strong hover:bg-[var(--pc-hover)]',
                          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--pc-focus)]',
                          'focus-visible:ring-offset-2 focus-visible:ring-offset-pc-base',
                        ].join(' ')}
                      >
                        {body}
                      </Link>
                    ) : (
                      <article
                        key={`${kind}:${entry.id}`}
                        className="flex w-full flex-col gap-3 rounded-[var(--radius-lg)] border border-pc-border bg-pc-surface p-5 text-left"
                      >
                        {body}
                      </article>
                    );
                  })}
                </div>
              </section>
            );
          })
      )}
    </div>
  );
}
