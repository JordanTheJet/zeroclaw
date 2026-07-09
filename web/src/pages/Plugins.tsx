import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Puzzle, Check, Circle, Download, ArrowRight } from 'lucide-react';
import type { PluginCatalogEntry } from '@/types/api';
import { getPlugins } from '@/lib/api';
import { Badge, Card, PageHeader } from '@/components/ui';
import type { BadgeTone } from '@/components/ui';

/** `kind` is a snake_case string, except an unrecognized registry capability
 *  which serializes as `{ other: string }`. Normalize to a plain key. */
function kindKey(k: PluginCatalogEntry['kind']): string {
  return typeof k === 'string' ? k : (k?.other ?? 'other');
}

const KIND_LABELS: Record<string, string> = {
  channel: 'Channels',
  tool: 'Tools',
  memory: 'Memory backends',
  observer: 'Observers',
  skill: 'Skills',
};

function kindLabel(k: string): string {
  return KIND_LABELS[k] ?? k.charAt(0).toUpperCase() + k.slice(1);
}

/** A compact "where does this come from" label from the resolved origin + flags. */
function sourceLabel(e: PluginCatalogEntry): string {
  if (e.origin === 'built_in') return e.installed ? 'Built-in + plugin' : 'Built-in';
  if (e.origin === 'plugin') return e.mirrors_builtin ? 'Plugin (mirror)' : 'Plugin';
  return 'Available';
}

function statusBadge(e: PluginCatalogEntry): {
  label: string;
  tone: BadgeTone;
  icon: typeof Check;
} {
  if (e.enabled) return { label: 'Enabled', tone: 'ok', icon: Check };
  if (e.origin === 'registry') return { label: 'Installable', tone: 'neutral', icon: Download };
  return { label: 'Off', tone: 'neutral', icon: Circle };
}

/** Where a card's "Configure" CTA lands: channels deep-link into the
 *  schema-driven Channels config (which owns per-alias enable/disable);
 *  everything else has no in-app config target yet. */
function configHref(e: PluginCatalogEntry): string | null {
  return kindKey(e.kind) === 'channel' ? `/config/channels/${e.id}` : null;
}

export default function Plugins() {
  const navigate = useNavigate();
  const [entries, setEntries] = useState<PluginCatalogEntry[]>([]);
  const [pluginsEnabled, setPluginsEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeKind, setActiveKind] = useState<string>('all');

  useEffect(() => {
    getPlugins()
      .then((res) => {
        setEntries(res.capabilities);
        setPluginsEnabled(res.plugins_enabled);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  const kinds = ['all', ...Array.from(new Set(entries.map((e) => kindKey(e.kind)))).sort()];
  const filtered =
    activeKind === 'all' ? entries : entries.filter((e) => kindKey(e.kind) === activeKind);

  const grouped = filtered.reduce<Record<string, PluginCatalogEntry[]>>((acc, item) => {
    const key = kindKey(item.kind);
    (acc[key] ??= []).push(item);
    return acc;
  }, {});

  if (error) {
    return (
      <div className="p-6">
        <div className="rounded-[var(--radius-md)] border border-status-error/25 bg-status-error/10 p-4 text-sm text-status-error">
          Failed to load plugins: {error}
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div
          className="h-8 w-8 border-2 rounded-full animate-spin border-pc-border"
          style={{ borderTopColor: 'var(--pc-accent)' }}
        />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <PageHeader
        title="Plugins"
        description="Built-in, installed, and installable capabilities. Toggle channels from their config; add installable ones with `zeroclaw plugin install`."
        actions={<Badge tone={pluginsEnabled ? 'ok' : 'neutral'}>
          plugins {pluginsEnabled ? 'on' : 'off'}
        </Badge>}
      />

      {/* Kind filter tabs */}
      <div className="flex flex-wrap gap-2">
        {kinds.map((k) => {
          const active = activeKind === k;
          return (
            <button
              key={k}
              type="button"
              onClick={() => setActiveKind(k)}
              className={[
                'px-3 h-7 inline-flex items-center rounded-[var(--radius-md)] text-[13px] font-medium transition-colors cursor-pointer border',
                active
                  ? 'bg-pc-accent border-transparent text-[#0b1220]'
                  : 'bg-transparent border-pc-border text-pc-text-secondary hover:bg-[var(--pc-hover)] hover:text-pc-text hover:border-pc-border-strong',
              ].join(' ')}
            >
              {k === 'all' ? 'All' : kindLabel(k)}
            </button>
          );
        })}
      </div>

      {Object.keys(grouped).length === 0 ? (
        <Card className="p-10 text-center">
          <Puzzle className="h-10 w-10 mx-auto mb-3 text-pc-text-faint" />
          <p className="text-sm text-pc-text-muted">No capabilities to show.</p>
        </Card>
      ) : (
        Object.entries(grouped)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([kind, items]) => (
            <div key={kind}>
              <h3 className="text-[11px] font-medium uppercase tracking-wider mb-3 text-pc-text-faint">
                {kindLabel(kind)}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {items.map((e) => {
                  const badge = statusBadge(e);
                  const BadgeIcon = badge.icon;
                  const href = configHref(e);
                  const title = e.display_name ?? e.id;
                  const body = (
                    <>
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <h4 className="text-sm font-medium truncate text-pc-text">
                            {title}
                            {e.version && (
                              <span className="text-pc-text-faint font-normal"> v{e.version}</span>
                            )}
                          </h4>
                          <p className="text-sm mt-1 line-clamp-2 text-pc-text-muted">
                            {e.description ?? sourceLabel(e)}
                          </p>
                        </div>
                        <Badge tone={badge.tone} className="flex-shrink-0">
                          <BadgeIcon className="h-3 w-3" />
                          {badge.label}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <Badge tone="neutral">{sourceLabel(e)}</Badge>
                        {href ? (
                          <span className="flex items-center gap-1 text-[13px] font-medium text-pc-accent">
                            Configure
                            <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                          </span>
                        ) : e.available && !e.installed ? (
                          <code className="text-[11px] text-pc-text-faint truncate">
                            plugin install {e.id}
                          </code>
                        ) : null}
                      </div>
                    </>
                  );
                  return href ? (
                    <button
                      key={`${kind}:${e.id}`}
                      type="button"
                      onClick={() => navigate(href)}
                      aria-label={`Configure: ${title}`}
                      className={[
                        'group p-5 w-full text-left flex flex-col gap-3 cursor-pointer',
                        'bg-pc-surface border border-pc-border rounded-[var(--radius-lg)]',
                        'transition-colors hover:bg-[var(--pc-hover)] hover:border-pc-border-strong',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--pc-focus)]',
                        'focus-visible:ring-offset-2 focus-visible:ring-offset-pc-base',
                      ].join(' ')}
                    >
                      {body}
                    </button>
                  ) : (
                    <div
                      key={`${kind}:${e.id}`}
                      className="p-5 w-full text-left flex flex-col gap-3 bg-pc-surface border border-pc-border rounded-[var(--radius-lg)]"
                    >
                      {body}
                    </div>
                  );
                })}
              </div>
            </div>
          ))
      )}
    </div>
  );
}
