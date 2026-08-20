import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';
import { getLogs, type LogEvent } from '@/lib/api';
import { t } from '@/lib/i18n';
import { Card } from '@/components/ui';

const PAGE_LIMIT = 100;
const POLL_INTERVAL_MS = 3000;
const EVENT_CAPACITY = 1000;

function severityTone(severity: number): string {
  if (severity >= 17) return 'bg-status-error';
  if (severity >= 13) return 'bg-status-warning';
  if (severity >= 9) return 'bg-status-info';
  return 'bg-pc-text-faint';
}

function formatTime(timestamp: string): string {
  return timestamp.match(/T(\d{2}:\d{2}:\d{2}(?:\.\d{3})?)/)?.[1] ?? timestamp;
}

function mergeEvents(current: LogEvent[], incoming: LogEvent[]): LogEvent[] {
  const byId = new Map<string, LogEvent>();
  for (const event of current) byId.set(event.id, event);
  for (const event of incoming) byId.set(event.id, event);
  return Array.from(byId.values())
    .sort((left, right) => right['@timestamp'].localeCompare(left['@timestamp']))
    .slice(0, EVENT_CAPACITY);
}

function EventRow({ event }: { event: LogEvent }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails =
    Object.keys(event.attributes ?? {}).length > 0 ||
    Object.keys(event.zeroclaw ?? {}).length > 0 ||
    Boolean(event.trace_id);

  return (
    <li className="relative grid grid-cols-[5rem_minmax(0,1fr)] gap-3 pb-4 last:pb-0">
      <div className="font-mono text-[11px] tabular-nums text-pc-text-faint">
        {formatTime(event['@timestamp'])}
      </div>
      <span
        className={`absolute left-[5.31rem] top-1.5 h-2 w-2 -translate-x-1/2 rounded-full ring-2 ring-pc-surface ${severityTone(event.severity_number)}`}
        aria-hidden
      />
      <div className="min-w-0 pl-3">
        <button
          type="button"
          disabled={!hasDetails}
          onClick={() => setExpanded((value) => !value)}
          className="group flex w-full items-start gap-2 text-left disabled:cursor-default"
        >
          <span className="mt-0.5 w-3 shrink-0 text-pc-text-faint">
            {hasDetails ? (
              expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />
            ) : null}
          </span>
          <span className="min-w-0">
            <span className="font-mono text-[11px] uppercase tracking-wide text-pc-text-muted">
              {event.severity_text} · {event.event.category}.{event.event.action}
            </span>
            <span className="mt-0.5 block break-words text-sm leading-5 text-pc-text">
              {event.message || t('run_detail.logs_no_message')}
            </span>
          </span>
        </button>
        {expanded ? (
          <pre className="mt-2 max-h-72 overflow-auto rounded border border-pc-border bg-pc-input p-3 text-[11px] leading-5 text-pc-text-secondary">
            {JSON.stringify(
              {
                trace_id: event.trace_id ?? undefined,
                zeroclaw: event.zeroclaw,
                attributes: event.attributes,
              },
              null,
              2,
            )}
          </pre>
        ) : null}
      </div>
    </li>
  );
}

interface RunLogsPanelProps {
  runId: string;
  active: boolean;
}

export default function RunLogsPanel({ runId, active }: RunLogsPanelProps) {
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [atEnd, setAtEnd] = useState(true);
  const [persistenceEnabled, setPersistenceEnabled] = useState(true);
  const [loading, setLoading] = useState(true);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestSeq = useRef(0);

  const loadLatest = useCallback(
    async (replace: boolean) => {
      const seq = ++requestSeq.current;
      if (replace) setLoading(true);
      try {
        const response = await getLogs({
          field_eq: { sop_run_id: runId },
          hide_internal: false,
          limit: PAGE_LIMIT,
        });
        if (seq !== requestSeq.current) return;
        setPersistenceEnabled(response.persistence_enabled ?? true);
        setError(null);
        setEvents((current) => (replace ? response.events : mergeEvents(current, response.events)));
        if (replace) {
          setCursor(response.next_cursor_line_offset ?? null);
          setAtEnd(response.at_end);
        }
      } catch (reason) {
        if (seq === requestSeq.current) {
          setError(reason instanceof Error ? reason.message : String(reason));
        }
      } finally {
        if (replace && seq === requestSeq.current) setLoading(false);
      }
    },
    [runId],
  );

  useEffect(() => {
    setEvents([]);
    setCursor(null);
    setAtEnd(true);
    setPersistenceEnabled(true);
    void loadLatest(true);
    return () => {
      requestSeq.current += 1;
    };
  }, [loadLatest]);

  useEffect(() => {
    if (!active) return;
    const interval = window.setInterval(() => void loadLatest(false), POLL_INTERVAL_MS);
    return () => window.clearInterval(interval);
  }, [active, loadLatest]);

  const loadOlder = useCallback(async () => {
    if (cursor === null || atEnd || loadingOlder) return;
    setLoadingOlder(true);
    try {
      const response = await getLogs({
        field_eq: { sop_run_id: runId },
        hide_internal: false,
        until_line_offset: cursor,
        limit: PAGE_LIMIT,
      });
      setEvents((current) => mergeEvents(current, response.events));
      setCursor(response.next_cursor_line_offset ?? null);
      setAtEnd(response.at_end);
      setError(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setLoadingOlder(false);
    }
  }, [atEnd, cursor, loadingOlder, runId]);

  const chronological = useMemo(() => [...events].reverse(), [events]);

  return (
    <Card className="overflow-hidden p-0">
      <div className="flex flex-wrap items-center gap-3 border-b border-pc-border px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-pc-text">{t('run_detail.logs_title')}</h2>
          <p className="mt-0.5 text-xs text-pc-text-muted">{t('run_detail.logs_subtitle')}</p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <span className="font-mono text-xs tabular-nums text-pc-text-muted">
            {events.length} {t('logs.events')}
          </span>
          <button
            type="button"
            onClick={() => void loadLatest(true)}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded border border-pc-border px-2 py-1 text-xs text-pc-text-secondary hover:bg-pc-elevated disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} aria-hidden />
            {t('run_detail.logs_refresh')}
          </button>
        </div>
      </div>

      {error ? <div className="border-b border-pc-border px-4 py-3 text-sm text-status-error">{error}</div> : null}
      {!persistenceEnabled ? (
        <div className="px-4 py-8 text-center text-sm text-pc-text-muted">
          {t('run_detail.logs_disabled')}
        </div>
      ) : loading && events.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-pc-text-muted">
          {t('run_detail.logs_loading')}
        </div>
      ) : chronological.length === 0 ? (
        <div className="px-4 py-8 text-center text-sm text-pc-text-muted">
          {t('run_detail.logs_empty')}
        </div>
      ) : (
        <div className="max-h-[34rem] overflow-auto px-4 py-4">
          <ol className="relative before:absolute before:bottom-1 before:left-[5.31rem] before:top-2 before:w-px before:bg-pc-border">
            {chronological.map((event) => <EventRow key={event.id} event={event} />)}
          </ol>
        </div>
      )}

      {!atEnd && persistenceEnabled ? (
        <div className="border-t border-pc-border px-4 py-2 text-center">
          <button
            type="button"
            onClick={() => void loadOlder()}
            disabled={loadingOlder}
            className="text-xs text-pc-accent hover:underline disabled:opacity-40"
          >
            {loadingOlder ? t('run_detail.logs_loading') : t('logs.load_older')}
          </button>
        </div>
      ) : null}
    </Card>
  );
}
