import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { toast } from 'sonner';
import { useLingui } from '@lingui/react';
import { RefreshCw } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import {
    candidateToUiConfig,
    uiConfigToCandidate,
    type AppSnapshot,
    type Capability,
    type HostPolicyConfig,
    type HostPolicySnapshot,
    type LineCountingConfig,
    type LineCountingEvents,
    type LineCountingStats,
    type LineCrossingCapabilities,
    type LineCrossingUiState,
    type LineTrack,
    type VideoStreamGrant,
    unavailableCapabilities,
} from '@/services/api/line-counting';
import LineToolbar from './lineCounting/LineToolbar';
import ConfigPage from './lineCounting/ConfigPage';
import AdvancedPage from './lineCounting/AdvancedPage';
import StatsAndEvents from './lineCounting/StatsAndEvents';
import VideoPreview, { type LineTrackDot } from './lineCounting/VideoPreview';

type EditPhase = 0 | 1 | 2;
type LcPage = 'realtime' | 'config' | 'advanced';
type SaveResult = 'lineCrossing.applied' | 'lineCrossing.conflict' | 'lineCrossing.unknownOutcome' | 'lineCrossing.saveUnavailable' | 'lineCrossing.sessionChanged';

const PAGES: Array<{ key: LcPage; labelKey: string }> = [
    { key: 'realtime', labelKey: 'sys.line_counting.page_realtime' },
    { key: 'config', labelKey: 'sys.line_counting.page_config' },
    { key: 'advanced', labelKey: 'sys.line_counting.page_advanced' },
];

const FRESH_FOR_MS = 10000;
const clampPm = (value: number) => Math.max(0, Math.min(1000, Math.round(value)));

function computeOutside(x1: number, y1: number, x2: number, y2: number, sign: number) {
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    let nx = -(y2 - y1);
    let ny = x2 - x1;
    const length = Math.hypot(nx, ny) || 1;
    nx /= length;
    ny /= length;
    return { ox: clampPm(mx + sign * nx * 150), oy: clampPm(my + sign * ny * 150) };
}

function isFresh<T>(capability: Capability<T>, now: number): capability is Extract<Capability<T>, { state: 'available' }> {
    return capability.state === 'available' && now - capability.observedAtMs <= FRESH_FOR_MS;
}

function capabilityOrUnavailable<T>(capability: Capability<T> | undefined): Capability<T> {
    return capability ?? { state: 'unavailable', reason: 'Capability state has not loaded' };
}

function sameSessionState(state: LineCrossingUiState | null, sessionGeneration: number): boolean {
    return state?.app.state === 'available' && state.app.value.sessionGeneration === sessionGeneration;
}

function isValidLine(config: LineCountingConfig | null): boolean {
    return !!config && (config.line.x1 !== config.line.x2 || config.line.y1 !== config.line.y2);
}

function resultMessage(outcome: 'APPLIED' | 'CONFLICT' | 'UNKNOWN' | 'UNAVAILABLE'): SaveResult {
    if (outcome === 'APPLIED') return 'lineCrossing.applied';
    if (outcome === 'CONFLICT') return 'lineCrossing.conflict';
    if (outcome === 'UNAVAILABLE') return 'lineCrossing.saveUnavailable';
    return 'lineCrossing.unknownOutcome';
}

export interface LineCountingModuleProps {
    capabilities?: LineCrossingCapabilities;
}

export default function LineCountingModule({ capabilities = unavailableCapabilities }: LineCountingModuleProps) {
    const { i18n } = useLingui();
    const [state, setState] = useState<LineCrossingUiState | null>(null);
    const stateRef = useRef<LineCrossingUiState | null>(null);
    const [now, setNow] = useState(Date.now());
    const [draft, setDraft] = useState<LineCountingConfig | null>(null);
    const [hostDraft, setHostDraft] = useState<HostPolicyConfig | null>(null);
    const [page, setPage] = useState<LcPage>('realtime');
    const [editMode, setEditMode] = useState(false);
    const [editPhase, setEditPhase] = useState<EditPhase>(0);
    const [saving, setSaving] = useState(false);
    const [savingHost, setSavingHost] = useState(false);
    const [resetBusy, setResetBusy] = useState(false);
    const [confirmResetStats, setConfirmResetStats] = useState(false);
    const [confirmResetLine, setConfirmResetLine] = useState(false);
    const [confirmTarget, setConfirmTarget] = useState(false);
    const [appFeedback, setAppFeedback] = useState<SaveResult | null>(null);
    const [hostFeedback, setHostFeedback] = useState<SaveResult | null>(null);
    const draftRef = useRef<LineCountingConfig | null>(null);
    const activeAppRef = useRef<AppSnapshot | null>(null);
    const appGenerationRef = useRef<string | null>(null);
    const hostGenerationRef = useRef<string | null>(null);

    const publishState = useCallback((next: LineCrossingUiState) => {
        const current = stateRef.current;
        if (current && next.revision < current.revision) return;
        stateRef.current = next;
        setState(next);
    }, []);

    useEffect(() => {
        let disposed = false;
        const unsubscribe = capabilities.subscribe((next) => {
            if (!disposed) publishState(next);
        });
        capabilities.readState()
            .then((next) => { if (!disposed) publishState(next); })
            .catch(async () => {
                if (!disposed) publishState(await unavailableCapabilities.readState());
            });
        return () => {
            disposed = true;
            unsubscribe();
        };
    }, [capabilities, publishState]);

    useEffect(() => {
        const interval = window.setInterval(() => setNow(Date.now()), 1000);
        return () => window.clearInterval(interval);
    }, []);

    const appCapability = capabilityOrUnavailable(state?.app);
    const appSnapshot = appCapability.state === 'available' ? appCapability.value : null;
    const activeConfig = appSnapshot ? candidateToUiConfig(appSnapshot.config) : null;
    const appFresh = isFresh(appCapability, now)
        && appSnapshot !== null
        && now - appSnapshot.observedAtMs <= FRESH_FOR_MS;
    const configWrite = capabilityOrUnavailable(state?.configWrite);
    const writeAllowed = appFresh && isFresh(configWrite, now) && configWrite.value;
    const statsResetCapability = capabilityOrUnavailable(state?.statsReset);
    const canResetStats = appFresh && isFresh(statsResetCapability, now) && statsResetCapability.value;
    const hostCapability = capabilityOrUnavailable(state?.hostPolicy);
    const hostPolicyFresh = isFresh(hostCapability, now)
        && now - (hostCapability.state === 'available' ? hostCapability.value.observedAtMs : now) <= FRESH_FOR_MS;
    const hostWriteCapability = capabilityOrUnavailable(state?.hostPolicyWrite);
    const hostWriteAllowed = hostPolicyFresh && isFresh(hostWriteCapability, now) && hostWriteCapability.value;
    const businessEnable = capabilityOrUnavailable(state?.businessEnable);
    const effectiveBusinessEnable = isFresh(businessEnable, now)
        ? businessEnable
        : businessEnable.state === 'available'
            ? { state: 'stale' as const, reason: 'Business Enable observation is stale' }
            : businessEnable;

    draftRef.current = draft;
    activeAppRef.current = appSnapshot;

    useEffect(() => {
        if (!appSnapshot) {
            setDraft(null);
            appGenerationRef.current = null;
            setEditMode(false);
            setEditPhase(0);
            return;
        }
        const nextGeneration = `${appSnapshot.sessionGeneration}:${appSnapshot.configGeneration}`;
        if (appGenerationRef.current !== nextGeneration) {
            appGenerationRef.current = nextGeneration;
            const nextConfig = candidateToUiConfig(appSnapshot.config);
            setDraft(nextConfig);
            draftRef.current = nextConfig;
            setEditMode(false);
            setEditPhase(0);
            if (!saving) setAppFeedback(null);
        }
    }, [appSnapshot?.sessionGeneration, appSnapshot?.configGeneration]);

    useEffect(() => {
        if (!hostCapability || hostCapability.state !== 'available') {
            setHostDraft(null);
            hostGenerationRef.current = null;
            return;
        }
        const snapshot = hostCapability.value;
        const nextGeneration = `${snapshot.sessionGeneration}:${snapshot.generation}`;
        if (hostGenerationRef.current !== nextGeneration) {
            hostGenerationRef.current = nextGeneration;
            setHostDraft({ ...snapshot.config });
            if (!savingHost) setHostFeedback(null);
        }
    }, [hostCapability.state, hostCapability.state === 'available' ? hostCapability.value.sessionGeneration : -1, hostCapability.state === 'available' ? hostCapability.value.generation : -1]);

    useEffect(() => {
        if (!writeAllowed && activeConfig) {
            setDraft(activeConfig);
            draftRef.current = activeConfig;
            setEditMode(false);
            setEditPhase(0);
        }
    }, [writeAllowed, appSnapshot?.sessionGeneration, appSnapshot?.configGeneration]);

    const dirty = useMemo(() => JSON.stringify(draft) !== JSON.stringify(activeConfig), [draft, activeConfig]);
    const targetChanged = !!draft && !!activeConfig && draft.target_class !== activeConfig.target_class;
    const lineValid = isValidLine(draft);

    const updateState = (update: (current: LineCrossingUiState) => LineCrossingUiState) => {
        const current = stateRef.current;
        if (!current) return;
        publishState(update(current));
    };

    const handleDraftChange = (patch: Partial<LineCountingConfig>) => {
        if (!writeAllowed) return;
        setDraft((previous) => previous ? { ...previous, ...patch } : previous);
    };

    const handleDraftLine = (x1: number, y1: number, x2: number, y2: number, ox: number, oy: number) => {
        if (!writeAllowed) return;
        setDraft((previous) => previous ? {
            ...previous,
            line: { ...previous.line, x1, y1, x2, y2, outside_x: ox, outside_y: oy },
        } : previous);
    };

    const handlePickPoint = useCallback((x: number, y: number) => {
        const current = draftRef.current;
        if (!current || !writeAllowed) return;
        if (editPhase === 0) {
            handleDraftLine(x, y, x, y, current.line.outside_x, current.line.outside_y);
            setEditPhase(1);
        } else if (editPhase === 1) {
            const { ox, oy } = computeOutside(current.line.x1, current.line.y1, x, y, 1);
            handleDraftLine(current.line.x1, current.line.y1, x, y, ox, oy);
            setEditPhase(2);
        } else {
            handleDraftLine(x, y, x, y, current.line.outside_x, current.line.outside_y);
            setEditPhase(1);
        }
    }, [editPhase, writeAllowed]);

    const handleDragEndpoint = useCallback((endpoint: 'start' | 'end', x: number, y: number) => {
        const current = draftRef.current;
        if (!current || !writeAllowed) return;
        const nextLine = { ...current.line };
        if (endpoint === 'start') {
            nextLine.x1 = x;
            nextLine.y1 = y;
        } else {
            nextLine.x2 = x;
            nextLine.y2 = y;
        }
        const mx = (current.line.x1 + current.line.x2) / 2;
        const my = (current.line.y1 + current.line.y2) / 2;
        const nx = -(current.line.y2 - current.line.y1);
        const ny = current.line.x2 - current.line.x1;
        const side = (current.line.outside_x - mx) * nx + (current.line.outside_y - my) * ny >= 0 ? 1 : -1;
        const outside = computeOutside(nextLine.x1, nextLine.y1, nextLine.x2, nextLine.y2, side);
        nextLine.outside_x = outside.ox;
        nextLine.outside_y = outside.oy;
        handleDraftLine(nextLine.x1, nextLine.y1, nextLine.x2, nextLine.y2, nextLine.outside_x, nextLine.outside_y);
        setEditPhase(2);
    }, [writeAllowed]);

    const handleFlipDirection = () => {
        const current = draftRef.current;
        if (!current || !writeAllowed || (current.line.x1 === current.line.x2 && current.line.y1 === current.line.y2)) return;
        const mx = (current.line.x1 + current.line.x2) / 2;
        const my = (current.line.y1 + current.line.y2) / 2;
        handleDraftLine(
            current.line.x1,
            current.line.y1,
            current.line.x2,
            current.line.y2,
            clampPm(2 * mx - current.line.outside_x),
            clampPm(2 * my - current.line.outside_y),
        );
    };

    const applyAppConfig = async (): Promise<boolean> => {
        const currentState = stateRef.current;
        const currentSnapshot = currentState?.app.state === 'available' ? currentState.app.value : null;
        const currentDraft = draftRef.current;
        if (!currentSnapshot || !currentDraft || !writeAllowed || !isValidLine(currentDraft)) {
            setAppFeedback('lineCrossing.saveUnavailable');
            return false;
        }
        const requestedSession = currentSnapshot.sessionGeneration;
        const expectedGeneration = currentSnapshot.configGeneration;
        setSaving(true);
        setAppFeedback(null);
        try {
            const outcome = await capabilities.applyConfig({
                sessionGeneration: requestedSession,
                expectedConfigGeneration: expectedGeneration,
                candidate: uiConfigToCandidate(currentDraft),
            });
            const latestState = stateRef.current;
            if (!sameSessionState(latestState, requestedSession)) {
                setAppFeedback('lineCrossing.sessionChanged');
                return false;
            }
            if (outcome.outcome !== 'APPLIED') {
                setAppFeedback(resultMessage(outcome.outcome));
                if (outcome.outcome === 'UNKNOWN') toast.error(i18n._('lineCrossing.unknownOutcome'));
                return false;
            }
            if (outcome.sessionGeneration !== requestedSession
                || outcome.snapshot.sessionGeneration !== requestedSession
                || outcome.snapshot.configGeneration !== outcome.configGeneration
                || outcome.configGeneration <= expectedGeneration) {
                setAppFeedback('lineCrossing.unknownOutcome');
                return false;
            }
            const returnedSnapshot = { ...outcome.snapshot, observedAtMs: Date.now() };
            updateState((current) => ({
                ...current,
                revision: current.revision + 1,
                app: { state: 'available', value: returnedSnapshot, observedAtMs: returnedSnapshot.observedAtMs },
            }));
            const saved = candidateToUiConfig(returnedSnapshot.config);
            setDraft(saved);
            draftRef.current = saved;
            setEditMode(false);
            setEditPhase(0);
            setAppFeedback('lineCrossing.applied');
            toast.success(i18n._('sys.line_counting.save_success'));
            return true;
        } catch {
            setAppFeedback('lineCrossing.unknownOutcome');
            return false;
        } finally {
            setSaving(false);
        }
    };

    const handleSave = async () => {
        if (!draft || !writeAllowed) {
            setAppFeedback('lineCrossing.saveUnavailable');
            return;
        }
        if (targetChanged) {
            setConfirmTarget(true);
            return;
        }
        await applyAppConfig();
    };

    const handleFinishDraw = async () => {
        if (!draft || !dirty || !lineValid) {
            setEditMode(false);
            setEditPhase(0);
            return;
        }
        setEditMode(false);
        setEditPhase(0);
        await handleSave();
    };

    const discardDraft = () => {
        const active = activeAppRef.current;
        if (active) {
            const reset = candidateToUiConfig(active.config);
            setDraft(reset);
            draftRef.current = reset;
        }
        setEditMode(false);
        setEditPhase(0);
        setConfirmTarget(false);
        setConfirmResetLine(false);
        setAppFeedback(null);
    };

    const resetStats = async () => {
        const currentState = stateRef.current;
        const currentSnapshot = currentState?.app.state === 'available' ? currentState.app.value : null;
        if (!currentSnapshot || !canResetStats) return;
        setConfirmResetStats(false);
        setResetBusy(true);
        try {
            const outcome = await capabilities.resetStats({ sessionGeneration: currentSnapshot.sessionGeneration });
            if (!sameSessionState(stateRef.current, currentSnapshot.sessionGeneration)) return;
            if (outcome.outcome !== 'APPLIED' || outcome.sessionGeneration !== currentSnapshot.sessionGeneration) {
                toast.error(outcome.outcome === 'UNKNOWN' ? i18n._('lineCrossing.unknownOutcome') : i18n._('lineCrossing.resetUnavailable'));
                return;
            }
            const fresh = await capabilities.readState();
            if (sameSessionState(fresh, currentSnapshot.sessionGeneration)) publishState(fresh);
            toast.success(i18n._('sys.line_counting.reset_success'));
        } catch {
            toast.error(i18n._('lineCrossing.unknownOutcome'));
        } finally {
            setResetBusy(false);
        }
    };

    const applyHostPolicy = async () => {
        const currentState = stateRef.current;
        const currentHost = currentState?.hostPolicy.state === 'available' ? currentState.hostPolicy.value : null;
        const currentApp = currentState?.app.state === 'available' ? currentState.app.value : null;
        const candidate = hostDraft;
        if (!currentHost || !currentApp || !candidate || !hostWriteAllowed || currentHost.sessionGeneration !== currentApp.sessionGeneration) {
            setHostFeedback('lineCrossing.saveUnavailable');
            return;
        }
        setSavingHost(true);
        setHostFeedback(null);
        try {
            const outcome = await capabilities.applyHostPolicy({
                sessionGeneration: currentHost.sessionGeneration,
                expectedGeneration: currentHost.generation,
                candidate,
            });
            if (!sameSessionState(stateRef.current, currentHost.sessionGeneration)) {
                setHostFeedback('lineCrossing.sessionChanged');
                return;
            }
            if (outcome.outcome !== 'APPLIED') {
                setHostFeedback(resultMessage(outcome.outcome));
                return;
            }
            if (outcome.sessionGeneration !== currentHost.sessionGeneration
                || outcome.snapshot.sessionGeneration !== currentHost.sessionGeneration
                || outcome.snapshot.generation !== outcome.generation
                || outcome.generation <= currentHost.generation) {
                setHostFeedback('lineCrossing.unknownOutcome');
                return;
            }
            const snapshot = { ...outcome.snapshot, observedAtMs: Date.now() };
            updateState((current) => ({
                ...current,
                revision: current.revision + 1,
                hostPolicy: { state: 'available', value: snapshot, observedAtMs: snapshot.observedAtMs },
            }));
            setHostDraft({ ...snapshot.config });
            setHostFeedback('lineCrossing.applied');
        } catch {
            setHostFeedback('lineCrossing.unknownOutcome');
        } finally {
            setSavingHost(false);
        }
    };

    const requestVideo = async () => {
        const currentState = stateRef.current;
        const currentSnapshot = currentState?.app.state === 'available' ? currentState.app.value : null;
        if (!currentSnapshot || !appFresh) return;
        try {
            const nextGrant = await capabilities.openVideoStream({ sessionGeneration: currentSnapshot.sessionGeneration });
            if (!sameSessionState(stateRef.current, currentSnapshot.sessionGeneration)) {
                if (nextGrant.state === 'available') nextGrant.value.release();
                return;
            }
            if (nextGrant.state === 'available' && nextGrant.value.sessionGeneration !== currentSnapshot.sessionGeneration) {
                nextGrant.value.release();
                return;
            }
            updateState((current) => ({ ...current, revision: current.revision + 1, video: nextGrant }));
        } catch {
            updateState((current) => ({ ...current, revision: current.revision + 1, video: { state: 'unavailable', reason: 'Video grant request failed' } }));
        }
    };

    const freshCapability = <T,>(capability: Capability<T> | undefined): Capability<T> => {
        const value = capabilityOrUnavailable(capability);
        return value.state === 'available' && !isFresh(value, now)
            ? { state: 'stale', reason: 'Capability observation is stale' }
            : value;
    };

    const appStateText = !state
        ? i18n._('sys.line_counting.loading')
        : appSnapshot && appFresh
            ? i18n._(appSnapshot.status.state === 'running' ? 'sys.line_counting.state_running' : appSnapshot.status.state === 'stopped' ? 'sys.line_counting.state_disabled' : 'lineCrossing.unknown')
            : appCapability.state === 'available' || appCapability.state === 'stale'
                ? i18n._('lineCrossing.stale')
                : i18n._('lineCrossing.unavailable');
    const tracksCapability = freshCapability(state?.tracks);
    const tracks: LineTrackDot[] = tracksCapability.state === 'available'
        ? tracksCapability.value.map((track: LineTrack) => ({ track_id: track.track_id, points: track.points }))
        : [];
    const currentVideo = capabilityOrUnavailable(state?.video);
    const videoCapability: Capability<VideoStreamGrant> = currentVideo.state === 'available'
        ? !appSnapshot || currentVideo.value.sessionGeneration !== appSnapshot.sessionGeneration
            ? { state: 'unavailable', reason: 'Video grant belongs to a different App session' }
            : currentVideo.value.expiresAtMs <= now
                ? { state: 'unavailable', reason: 'Video grant has expired' }
                : currentVideo
        : currentVideo;
    const draftLineValid = isValidLine(draft);

    return (
        <div className="flex flex-col gap-3 p-4" data-testid="lc-module">
            <div role="status" data-testid="lc-app-state" data-state={appFresh ? 'available' : appCapability.state === 'available' ? 'stale' : appCapability.state} title={appCapability.state === 'unavailable' || appCapability.state === 'stale' ? appCapability.reason : undefined}>
                {appStateText}
            </div>
            <Card className="overflow-hidden">
                <CardContent className="p-0">
                    <VideoPreview
                        config={activeConfig}
                        draft={draft}
                        editMode={editMode}
                        editPhase={editPhase}
                        writeAllowed={writeAllowed}
                        state={appSnapshot?.status.state}
                        tracks={tracks}
                        video={videoCapability}
                        onRequestVideo={requestVideo}
                        onPickPoint={handlePickPoint}
                        onDragEndpoint={handleDragEndpoint}
                    />
                </CardContent>
            </Card>

            <LineToolbar
                editMode={editMode}
                editPhase={editPhase}
                disabled={!writeAllowed}
                hasLine={!!draft && (draft.line.x1 !== draft.line.x2 || draft.line.y1 !== draft.line.y2)}
                onToggleEdit={() => {
                    if (!writeAllowed) return;
                    setEditMode((value) => !value);
                    setEditPhase(0);
                }}
                onFinishDraw={handleFinishDraw}
                onFlipDirection={handleFlipDirection}
                onResetLine={() => { if (writeAllowed) setConfirmResetLine(true); }}
            />
            {editMode && <div className="flex justify-end">
                <Button variant="outline" onClick={discardDraft} disabled={!dirty} data-testid="lc-discard">
                    {i18n._('lineCrossing.discard')}
                </Button>
            </div>}

            <div className="grid grid-cols-3 border-b border-gray-200" role="tablist" data-testid="lc-page-tabs">
                {PAGES.map((item) => (
                    <button
                        key={item.key}
                        role="tab"
                        aria-selected={page === item.key}
                        data-testid={`lc-tab-${item.key}`}
                        onClick={() => setPage(item.key)}
                        className={`-mb-px border-b-2 px-2 py-2 text-center text-sm transition-colors ${page === item.key ? 'border-primary font-medium text-primary' : 'border-transparent text-gray-500 hover:text-gray-800'}`}
                    >
                        {i18n._(item.labelKey)}
                    </button>
                ))}
            </div>

            {page === 'realtime' && <div className="space-y-3" data-testid="lc-page-realtime">
                <StatsAndEvents stats={freshCapability(state?.stats) as Capability<LineCountingStats>} events={freshCapability(state?.events) as Capability<LineCountingEvents>} targetClass={appSnapshot?.status.target_class ?? ''} />
                <div className="flex justify-end">
                    <Button variant="outline" onClick={() => setConfirmResetStats(true)} disabled={!canResetStats || resetBusy} data-testid="lc-reset-stats">
                        {resetBusy ? <RefreshCw className="h-4 w-4 animate-spin" /> : i18n._('sys.line_counting.reset_stats')}
                    </Button>
                </div>
            </div>}

            {page === 'config' && <>
                {activeConfig && appSnapshot
                    ? <ConfigPage config={draft ?? activeConfig} status={appSnapshot.status} businessEnable={effectiveBusinessEnable} writeAllowed={writeAllowed} onChange={handleDraftChange} />
                    : <p data-testid="lc-config-unavailable">{i18n._('lineCrossing.unavailable')}</p>}
                <div className="flex justify-end gap-2 pt-1" data-testid="lc-save-bar">
                    {dirty && <Button variant="outline" onClick={discardDraft} data-testid="lc-discard-config">{i18n._('lineCrossing.discard')}</Button>}
                    <Button onClick={handleSave} disabled={!draft || !writeAllowed || saving || !draftLineValid} data-testid="lc-save-config">
                        {saving ? i18n._('sys.line_counting.saving') : i18n._('common.save')}
                    </Button>
                    {appFeedback && <span role="status" data-testid="lc-save-status">{i18n._(appFeedback)}</span>}
                </div>
            </>}

            {page === 'advanced' && <AdvancedPage
                config={draft}
                hostPolicy={freshCapability(state?.hostPolicy) as Capability<HostPolicySnapshot>}
                appWriteAllowed={writeAllowed}
                hostWriteAllowed={hostWriteAllowed}
                appSaving={saving}
                hostSaving={savingHost}
                appFeedback={appFeedback}
                hostFeedback={hostFeedback}
                onAppChange={handleDraftChange}
                onHostChange={(patch) => {
                    if (hostWriteAllowed) setHostDraft((current) => current ? { ...current, ...patch } : current);
                }}
                onSaveApp={handleSave}
                onSaveHost={applyHostPolicy}
            />}

            {confirmTarget && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="lc-confirm-dialog">
                <div className="w-80 space-y-3 rounded-lg bg-white p-5">
                    <h4 className="text-sm font-semibold">{i18n._('sys.line_counting.confirm_target_title')}</h4>
                    <p className="text-xs text-gray-500">{i18n._('sys.line_counting.confirm_target_body')}</p>
                    <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => setConfirmTarget(false)}>{i18n._('common.cancel')}</Button>
                        <Button size="sm" onClick={async () => { setConfirmTarget(false); await applyAppConfig(); }}>{i18n._('common.confirm')}</Button>
                    </div>
                </div>
            </div>}

            {confirmResetStats && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="lc-reset-dialog">
                <div className="w-80 space-y-3 rounded-lg bg-white p-5">
                    <h4 className="text-sm font-semibold">{i18n._('sys.line_counting.reset_stats_title')}</h4>
                    <p className="text-xs text-gray-500">{i18n._('sys.line_counting.reset_stats_body')}</p>
                    <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => setConfirmResetStats(false)}>{i18n._('common.cancel')}</Button>
                        <Button size="sm" onClick={resetStats} disabled={!canResetStats}>{i18n._('sys.line_counting.confirm_reset')}</Button>
                    </div>
                </div>
            </div>}

            {confirmResetLine && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" data-testid="lc-reset-line-dialog">
                <div className="w-80 space-y-3 rounded-lg bg-white p-5">
                    <h4 className="text-sm font-semibold">{i18n._('lineCrossing.resetLineTitle')}</h4>
                    <p className="text-xs text-gray-500">{i18n._('lineCrossing.resetLineBody')}</p>
                    <div className="flex justify-end gap-2">
                        <Button size="sm" variant="outline" onClick={() => setConfirmResetLine(false)}>{i18n._('common.cancel')}</Button>
                        <Button size="sm" onClick={() => {
                            handleDraftLine(500, 500, 500, 500, 500, 500);
                            setEditMode(false);
                            setEditPhase(0);
                            setConfirmResetLine(false);
                        }}>{i18n._('lineCrossing.confirmResetLine')}</Button>
                    </div>
                </div>
            </div>}
        </div>
    );
}
