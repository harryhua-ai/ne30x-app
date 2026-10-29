import { useLingui } from '@lingui/react';
import { Card, CardContent } from '@/components/ui/card';
import type { Capability, LineCountingStats, LineCountingEvents, StorageHealth } from '@/services/api/line-counting';

export interface StatsAndEventsProps {
    stats: Capability<LineCountingStats>;
    events: Capability<LineCountingEvents>;
    targetClass: string;
    storage?: StorageHealth;
}

function StatCell({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
    return (
        <div className="flex min-w-0 flex-col items-center" data-testid="lc-stat-cell">
            <span className={`max-w-full truncate font-mono text-[28px] font-semibold leading-[34px] tabular-nums ${accent ?? 'text-gray-800'}`}>{value}</span>
            <span className="mt-1 max-w-full truncate text-[13px] leading-none text-gray-500">{label}</span>
        </div>
    );
}

const COLS = 'grid grid-cols-[64px_minmax(64px,1.3fr)_64px_minmax(56px,1fr)] lg:grid-cols-[80px_150px_80px_minmax(0,1fr)] items-center gap-x-2 px-1';

export default function StatsAndEvents({ stats, events, targetClass, storage }: StatsAndEventsProps) {
    const { i18n } = useLingui();
    const statValues = stats.state === 'available' ? stats.value : null;
    const eventValues = events.state === 'available' ? events.value : null;
    const list = eventValues?.events ?? [];
    const storageDegraded = storage !== undefined && storage.state !== 'ok';
    const unavailableText = (state: Capability<unknown>['state']) => state === 'stale'
        ? i18n._('lineCrossing.stale')
        : i18n._('lineCrossing.unavailable');

    return (
        <div className="flex flex-col gap-3 lg:flex-row">
            <Card className="h-72 w-full gap-0 py-0 lg:w-[38%] lg:shrink-0">
                <CardContent className="flex min-h-0 flex-1 flex-col p-5">
                    <h4 className="text-base font-semibold leading-6 text-gray-800">{i18n._('sys.line_counting.stats_title')}</h4>
                    <div className="flex min-h-0 flex-1 items-center justify-center">
                        {statValues
                            ? <div className="grid w-[240px] max-w-full grid-cols-[repeat(2,minmax(0,1fr))] gap-x-4">
                                <StatCell label={i18n._('sys.line_counting.stat_window_in')} value={statValues.window.in} accent="text-emerald-600" />
                                <StatCell label={i18n._('sys.line_counting.stat_window_out')} value={statValues.window.out} accent="text-rose-600" />
                                <div className="col-span-2 my-3 h-px bg-gray-100" />
                                <StatCell label={i18n._('sys.line_counting.stat_total_in')} value={statValues.total.in} accent="text-emerald-600" />
                                <StatCell label={i18n._('sys.line_counting.stat_total_out')} value={statValues.total.out} accent="text-rose-600" />
                            </div>
                            : <p data-testid="lc-stats-unavailable">{unavailableText(stats.state)}</p>}
                    </div>
                </CardContent>
            </Card>
            <Card className="h-72 w-full gap-0 py-0 lg:min-w-0 lg:flex-1">
                <CardContent className="flex min-h-0 flex-1 flex-col p-5">
                    <h4 className="text-base font-semibold leading-6 text-gray-800">{i18n._('sys.line_counting.events_title')}</h4>
                    <div className={`${COLS} mt-4 h-7 border-b border-gray-100 text-[10px] text-gray-400 md:text-[11px]`}>
                        <span>{i18n._('sys.line_counting.col_track')}</span>
                        <span>{i18n._('sys.line_counting.col_object')}</span>
                        <span>{i18n._('sys.line_counting.col_direction')}</span>
                        <span>{i18n._('sys.line_counting.col_time')}</span>
                    </div>
                    <div className="min-h-0 flex-1 overflow-y-auto pr-1" data-testid="lc-event-list">
                        {!eventValues
                            ? <div data-testid="lc-events-unavailable" className="flex h-full items-center justify-center text-xs text-gray-400">{storageDegraded ? i18n._('lineCrossing.storageDegraded') : unavailableText(events.state)}</div>
                            : list.length === 0
                                ? <div className="flex h-full items-center justify-center text-xs text-gray-400">{i18n._('sys.line_counting.no_events')}</div>
                                : <ul>
                                    {list.map((event) => {
                                        const eventClass = event.target_class || targetClass || '—';
                                        const ageMs = Math.max(0, eventValues.server_now_ms - event.timestamp_ms);
                                        return (
                                            <li key={event.sequence} className={`${COLS} h-[30px] border-b border-gray-50 font-mono text-xs`}>
                                                <span className="text-gray-500">#{event.track_id}</span>
                                                <span className="truncate text-gray-700" data-testid="lc-event-class">{eventClass}</span>
                                                <span className={event.direction === 'in' ? 'font-semibold text-emerald-600' : 'font-semibold text-rose-600'}>
                                                    {event.direction === 'in' ? 'IN' : 'OUT'}
                                                </span>
                                                <span className="truncate text-gray-400">{i18n._('sys.line_counting.seconds_ago').replace('{n}', String(Math.round(ageMs / 1000)))}</span>
                                            </li>
                                        );
                                    })}
                                </ul>}
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
