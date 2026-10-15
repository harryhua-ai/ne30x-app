import type {
    AppSnapshot,
    ApplyOutcome,
    Capability,
    HostApplyOutcome,
    HostPolicyConfig,
    HostPolicySnapshot,
    LineCrossingCapabilities,
    LineCrossingConfigCandidate,
    LineCrossingUiState,
    ResetOutcome,
    VideoStreamGrant,
} from '../../../apps/line-crossing/ui/src/services/api/line-counting';

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const observedAtMs = () => Date.now();
const available = <T,>(value: T): Capability<T> => ({ state: 'available', value, observedAtMs: observedAtMs() });

const initialCandidate: LineCrossingConfigCandidate = {
    schema: 1,
    counter_name: 'Counter Test',
    target_class_name: 'person',
    line: { x1: 250, y1: 500, x2: 750, y2: 500, outside_x: 500, outside_y: 350 },
    conf_threshold_permille: 550,
    max_dist_permille: 350,
    track_history_k: 8,
    max_miss: 12,
    k_confirm: 2,
    tracks_report_enable: true,
    heat_grid_enable: false,
    window_minutes: 60,
};

function createGrant(sessionGeneration: number, url: string, onRelease: () => void): VideoStreamGrant {
    let released = false;
    return {
        url,
        sessionGeneration,
        expiresAtMs: Date.now() + 120000,
        release: () => {
            if (released) return;
            released = true;
            onRelease();
        },
    };
}

export function createTestCapabilities(url: URL) {
    const appSnapshot: AppSnapshot = {
        sessionGeneration: 8,
        configGeneration: 12,
        observedAtMs: observedAtMs(),
        config: clone(initialCandidate),
        status: {
            state: 'running',
            target_class: 'person',
            model: {
                name: 'Line Crossing Test Model',
                version: 'fixture',
                postprocess_type: 'yolo',
                generation: 3,
                classes: [{ id: 0, name: 'person' }, { id: 1, name: 'bicycle' }],
            },
        },
    };
    const hostSnapshot: HostPolicySnapshot = {
        sessionGeneration: 8,
        generation: 4,
        observedAtMs: observedAtMs(),
        config: { mqtt_enabled: false, webhook_enabled: true, backlog_capacity: 32 },
    };
    let releasedGrants = 0;
    const streamUrl = `ws://${url.host}/stream?grant=fixture`;
    let state: LineCrossingUiState = {
        revision: 1,
        app: available(appSnapshot),
        configWrite: available(true),
        businessEnable: { state: 'unavailable', reason: 'Business Enable capability unavailable in fixture' },
        stats: available({ window: { in: 7, out: 3 }, total: { in: 107, out: 43 } }),
        events: available({
            server_now_ms: Date.now(),
            events: [{ sequence: 2, timestamp_ms: Date.now() - 4000, track_id: 24, direction: 'in', target_class: 'person' }],
        }),
        tracks: available([{ track_id: 24, points: [{ x: 200, y: 500 }, { x: 300, y: 500 }, { x: 400, y: 500 }] }]),
        statsReset: available(true),
        hostPolicy: available(hostSnapshot),
        hostPolicyWrite: available(true),
        video: available(createGrant(8, streamUrl, () => { releasedGrants += 1; })),
    };
    const listeners = new Set<(next: LineCrossingUiState) => void>();
    const appCalls: unknown[] = [];
    const hostCalls: unknown[] = [];
    const resetCalls: unknown[] = [];
    let nextOutcome: 'APPLIED' | 'UNKNOWN' | 'CONFLICT' | 'MISMATCH_SESSION' = 'APPLIED';
    let delayNextApply = false;
    let pendingResolve: (() => void) | null = null;

    const emit = (patch: Partial<LineCrossingUiState>) => {
        state = { ...state, ...patch, revision: state.revision + 1 };
        for (const listener of listeners) listener(state);
    };

    const freshApp = (): AppSnapshot => state.app.state === 'available' ? state.app.value : appSnapshot;

    const makeAppOutcome = (request: { sessionGeneration: number; expectedConfigGeneration: number; candidate: LineCrossingConfigCandidate }): ApplyOutcome => {
        const base = freshApp();
        if (nextOutcome === 'UNKNOWN') return { outcome: 'UNKNOWN', reason: 'fixture unknown result' };
        if (nextOutcome === 'CONFLICT') return { outcome: 'CONFLICT', reason: 'fixture generation conflict' };
        const sessionGeneration = nextOutcome === 'MISMATCH_SESSION' ? request.sessionGeneration + 1 : request.sessionGeneration;
        const snapshot: AppSnapshot = {
            ...base,
            sessionGeneration,
            configGeneration: request.expectedConfigGeneration + 1,
            observedAtMs: observedAtMs(),
            config: clone(request.candidate),
            status: { ...base.status, target_class: request.candidate.target_class_name },
        };
        nextOutcome = 'APPLIED';
        return { outcome: 'APPLIED', sessionGeneration, configGeneration: snapshot.configGeneration, snapshot };
    };

    const capabilities: LineCrossingCapabilities = {
        readState: async () => state,
        subscribe: (listener) => {
            listeners.add(listener);
            return () => listeners.delete(listener);
        },
        applyConfig: async (request) => {
            appCalls.push(clone(request));
            if (delayNextApply) {
                delayNextApply = false;
                return new Promise<ApplyOutcome>((resolve) => {
                    pendingResolve = () => {
                        pendingResolve = null;
                        resolve(makeAppOutcome(request));
                    };
                });
            }
            if (state.app.state !== 'available' || state.app.value.sessionGeneration !== request.sessionGeneration || state.app.value.configGeneration !== request.expectedConfigGeneration) {
                return { outcome: 'CONFLICT', reason: 'fixture generation conflict' };
            }
            const result = makeAppOutcome(request);
            if (result.outcome === 'APPLIED' && result.snapshot.sessionGeneration === state.app.value.sessionGeneration) {
                emit({ app: available({ ...result.snapshot, observedAtMs: observedAtMs() }) });
            }
            return result;
        },
        applyHostPolicy: async (request) => {
            hostCalls.push(clone(request));
            if (state.hostPolicy.state !== 'available' || state.hostPolicy.value.sessionGeneration !== request.sessionGeneration || state.hostPolicy.value.generation !== request.expectedGeneration) {
                return { outcome: 'CONFLICT', reason: 'fixture Host generation conflict' };
            }
            const snapshot: HostPolicySnapshot = {
                ...state.hostPolicy.value,
                generation: request.expectedGeneration + 1,
                observedAtMs: observedAtMs(),
                config: clone(request.candidate),
            };
            emit({ hostPolicy: available(snapshot) });
            const result: HostApplyOutcome = { outcome: 'APPLIED', sessionGeneration: request.sessionGeneration, generation: snapshot.generation, snapshot };
            return result;
        },
        resetStats: async (request) => {
            resetCalls.push(clone(request));
            if (state.app.state !== 'available' || state.app.value.sessionGeneration !== request.sessionGeneration) return { outcome: 'CONFLICT' };
            const result: ResetOutcome = { outcome: 'APPLIED', sessionGeneration: request.sessionGeneration };
            emit({ stats: available({ window: { in: 0, out: 0 }, total: { in: 0, out: 0 } }), events: available({ server_now_ms: Date.now(), events: [] }) });
            return result;
        },
        openVideoStream: async ({ sessionGeneration }) => {
            if (state.app.state !== 'available' || state.app.value.sessionGeneration !== sessionGeneration) return { state: 'unavailable', reason: 'Fixture App session changed' };
            const grant = createGrant(sessionGeneration, streamUrl, () => { releasedGrants += 1; });
            const value = available(grant);
            emit({ video: value });
            return value;
        },
    };

    const testApi = {
        getCalls: () => ({ app: appCalls, host: hostCalls, reset: resetCalls }),
        getState: () => state,
        getReleasedGrants: () => releasedGrants,
        revokeConfigWrite: () => emit({ configWrite: { state: 'unavailable', reason: 'Fixture permission revoked' } }),
        restoreConfigWrite: () => emit({ configWrite: available(true) }),
        revokeVideo: () => emit({ video: { state: 'unavailable', reason: 'Fixture video permission revoked' } }),
        makeAppStale: () => {
            const snapshot = freshApp();
            const old = Date.now() - 11000;
            emit({ app: { state: 'available', value: { ...snapshot, observedAtMs: old }, observedAtMs: old } });
        },
        setNextOutcome: (value: typeof nextOutcome) => { nextOutcome = value; },
        delayNextApply: () => { delayNextApply = true; },
        resolvePendingApply: () => pendingResolve?.(),
        changeSession: () => {
            const old = freshApp();
            const next = { ...old, sessionGeneration: old.sessionGeneration + 1, observedAtMs: observedAtMs() };
            emit({
                app: available(next),
                configWrite: available(true),
                video: { state: 'unavailable', reason: 'Fixture session changed' },
                hostPolicy: state.hostPolicy.state === 'available'
                    ? available({ ...state.hostPolicy.value, sessionGeneration: next.sessionGeneration, observedAtMs: observedAtMs() })
                    : state.hostPolicy,
            });
        },
        makeHostUnavailable: () => emit({ hostPolicy: { state: 'unavailable', reason: 'Fixture Host policy unavailable' }, hostPolicyWrite: { state: 'unavailable', reason: 'Fixture Host write unavailable' } }),
    };

    return { capabilities, testApi };
}
