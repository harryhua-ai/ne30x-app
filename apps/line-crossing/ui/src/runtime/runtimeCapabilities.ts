import type {
    AppSnapshot,
    Capability,
    EnableApplyOutcome,
    HostApplyOutcome,
    HostPolicySnapshot,
    LineCountingEvent,
    LineCountingEvents,
    LineCountingStats,
    LineCountingStatus,
    LineCrossingCapabilities,
    LineCrossingConfigCandidate,
    LineCrossingUiState,
    LineTrack,
    ResetOutcome,
    StorageHealth,
    VideoStreamGrant,
} from '../services/api/line-counting';
import {
    BRIDGE_APP_ID,
    isPlainObject,
    validateIdentity,
    type BridgeEvent,
    type BridgeGrant,
    type BridgeIdentity,
    type BridgeOp,
    type BridgeOutcome,
} from './bridgeProtocol';
import { BridgeSession, type BridgeNotification, type RequestOutcome } from './bridgeSession';

const DEFAULT_POLL_INTERVAL_MS = 5000;

type Validation<T> = { ok: true; value: T } | { ok: false; reason: string };

const failure = (reason: string): { ok: false; reason: string } => ({ ok: false, reason });

const isInt = (value: unknown, min: number, max: number): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;

const isString = (value: unknown, max: number): value is string =>
    typeof value === 'string' && value.length >= 1 && value.length <= max;

const hasKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
    if (Object.keys(value).length !== keys.length) return false;
    return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
};

const validatePoint = (value: unknown): Validation<{ x: number; y: number }> => {
    if (!isPlainObject(value) || !hasKeys(value, ['x', 'y'])) return failure('point fields invalid');
    if (!isInt(value.x, 0, 1000) || !isInt(value.y, 0, 1000)) return failure('point coordinates out of range');
    return { ok: true, value: { x: value.x, y: value.y } };
};

const validateCandidateConfig = (value: unknown): Validation<LineCrossingConfigCandidate> => {
    if (!isPlainObject(value) || !hasKeys(value, [
        'schema', 'counter_name', 'target_class_name', 'line', 'conf_threshold_permille', 'max_dist_permille',
        'track_history_k', 'max_miss', 'k_confirm', 'tracks_report_enable', 'heat_grid_enable', 'window_minutes',
    ])) return failure('config fields do not match schema 1');
    if (value.schema !== 1) return failure('config schema is not 1');
    if (!isString(value.counter_name, 128) || !isString(value.target_class_name, 64)) return failure('config names invalid');
    if (!isInt(value.conf_threshold_permille, 0, 1000) || !isInt(value.max_dist_permille, 0, 1000)) return failure('config thresholds out of range');
    if (!isInt(value.track_history_k, 0, 1024) || !isInt(value.max_miss, 0, 65535) || !isInt(value.k_confirm, 0, 1024)) return failure('config tracking out of range');
    if (typeof value.tracks_report_enable !== 'boolean' || typeof value.heat_grid_enable !== 'boolean') return failure('config reporting flags invalid');
    if (!isInt(value.window_minutes, 1, 1440)) return failure('config window_minutes out of range');
    const line = value.line;
    if (!isPlainObject(line) || !hasKeys(line, ['x1', 'y1', 'x2', 'y2', 'outside_x', 'outside_y'])) return failure('config line fields invalid');
    for (const key of ['x1', 'y1', 'x2', 'y2', 'outside_x', 'outside_y']) {
        if (!isInt(line[key], 0, 1000)) return failure(`config line.${key} out of range`);
    }
    return { ok: true, value: value as unknown as LineCrossingConfigCandidate };
};

const validateStatus = (value: unknown): Validation<LineCountingStatus> => {
    if (!isPlainObject(value) || !hasKeys(value, ['state', 'target_class', 'model'])) return failure('status fields invalid');
    if (value.state !== 'running' && value.state !== 'stopped' && value.state !== 'unknown') return failure('status state unknown');
    if (!isString(value.target_class, 64)) return failure('status target_class invalid');
    const model = value.model;
    if (!isPlainObject(model) || !hasKeys(model, ['name', 'version', 'postprocess_type', 'generation', 'classes'])) return failure('status model fields invalid');
    if (!isString(model.name, 128) || !isString(model.version, 64) || !isString(model.postprocess_type, 32)) return failure('status model strings invalid');
    if (!isInt(model.generation, 0, 4294967295)) return failure('status model generation invalid');
    if (!Array.isArray(model.classes) || model.classes.length > 64) return failure('status model classes unbounded');
    for (const item of model.classes) {
        if (!isPlainObject(item) || !hasKeys(item, ['id', 'name'])) return failure('model class fields invalid');
        if (!isInt(item.id, 0, 4096) || !isString(item.name, 64)) return failure('model class values invalid');
    }
    return { ok: true, value: value as unknown as LineCountingStatus };
};

const validateStats = (value: unknown): Validation<LineCountingStats> => {
    if (!isPlainObject(value) || !hasKeys(value, ['window', 'total'])) return failure('stats fields invalid');
    for (const key of ['window', 'total'] as const) {
        const group = value[key];
        if (!isPlainObject(group) || !hasKeys(group, ['in', 'out'])) return failure(`stats.${key} fields invalid`);
        if (!isInt(group.in, 0, Number.MAX_SAFE_INTEGER) || !isInt(group.out, 0, Number.MAX_SAFE_INTEGER)) return failure(`stats.${key} counters invalid`);
    }
    return { ok: true, value: value as unknown as LineCountingStats };
};

const adaptSnapshotV4 = (value: unknown, sessionGeneration: number): unknown => {
    if (!isPlainObject(value) || value.schema !== 'line-crossing/1' || !isPlainObject(value.active_config)) {
        return value;
    }
    const model = isPlainObject(value.model) ? value.model : {};
    const counters = isPlainObject(value.counters) ? value.counters : {};
    const cumulative = isPlainObject(value.cumulative) ? value.cumulative : {};
    const cfg = value.active_config;
    const line = isPlainObject(cfg.line) ? cfg.line : {};
    const outside = isPlainObject(cfg.outside) ? cfg.outside : {};
    const targetClass = typeof model.target_class === 'string' ? model.target_class : '';
    return {
        session_generation: sessionGeneration,
        config_generation: value.config_generation,
        config: {
            schema: 1,
            counter_name: cfg.counter_name,
            target_class_name: cfg.target_class_name,
            line: {
                x1: line.x1_permille,
                y1: line.y1_permille,
                x2: line.x2_permille,
                y2: line.y2_permille,
                outside_x: outside.x_permille,
                outside_y: outside.y_permille,
            },
            conf_threshold_permille: cfg.conf_threshold_permille,
            max_dist_permille: cfg.max_dist_permille,
            track_history_k: cfg.track_history_k,
            max_miss: cfg.max_miss,
            k_confirm: cfg.k_confirm,
            tracks_report_enable: cfg.tracks_report_enable,
            heat_grid_enable: cfg.heat_grid_enable,
            window_minutes: cfg.window_minutes,
        },
        status: {
            state: value.enable_state === 'disabled'
                ? 'stopped'
                : value.app_state === 'running' ? 'running' : 'unknown',
            target_class: targetClass,
            model: {
                name: 'line-crossing',
                version: '4',
                postprocess_type: 'unreported',
                generation: typeof model.generation === 'number' ? model.generation : 0,
                classes: targetClass ? [{ id: 0, name: targetClass }] : [],
            },
        },
        stats: {
            window: { in: counters.in ?? 0, out: counters.out ?? 0 },
            total: { in: cumulative.in ?? 0, out: cumulative.out ?? 0 },
        },
        ...(isPlainObject(value.storage) ? { storage: value.storage } : {}),
    };
};

const snapshotPayloadKeys = ['session_generation', 'config_generation', 'config', 'status', 'stats'] as const;

const validateStorageHealth = (value: unknown): Validation<StorageHealth> => {
    if (!isPlainObject(value) || !hasKeys(value, ['state', 'withheld'])) return failure('snapshot storage fields invalid');
    if (typeof value.withheld !== 'boolean') return failure('snapshot storage withheld invalid');
    if (value.state !== 'ok' && value.state !== 'none' && value.state !== 'degraded' && value.state !== 'corrupt' && value.state !== 'conflict' && value.state !== 'unknown') return failure('snapshot storage state unknown');
    return { ok: true, value: { state: value.state, withheld: value.withheld } };
};

const validateSnapshotPayload = (value: unknown): Validation<{
    session_generation: number;
    config_generation: number;
    config: LineCrossingConfigCandidate;
    status: LineCountingStatus;
    stats: LineCountingStats | null;
    storage?: StorageHealth;
}> => {
    if (!isPlainObject(value)) return failure('snapshot is not an object');
    const hasStats = Object.prototype.hasOwnProperty.call(value, 'stats');
    const hasStorage = Object.prototype.hasOwnProperty.call(value, 'storage');
    const baseKeys = hasStats ? snapshotPayloadKeys : snapshotPayloadKeys.slice(0, 4);
    if (!hasKeys(value, hasStorage ? [...baseKeys, 'storage'] : baseKeys)) return failure('snapshot fields do not match the v1 schema');
    if (!isInt(value.session_generation, 0, 4294967295) || !isInt(value.config_generation, 0, 4294967295)) return failure('snapshot generations invalid');
    const config = validateCandidateConfig(value.config);
    if (!config.ok) return config;
    const status = validateStatus(value.status);
    if (!status.ok) return status;
    let storage: StorageHealth | undefined;
    if (hasStorage) {
        const checked = validateStorageHealth(value.storage);
        if (!checked.ok) return checked;
        storage = checked.value;
    }
    let stats: LineCountingStats | null = null;
    if (hasStats) {
        const checked = validateStats(value.stats);
        if (!checked.ok) return checked;
        stats = checked.value;
    }
    return {
        ok: true,
        value: {
            session_generation: value.session_generation,
            config_generation: value.config_generation,
            config: config.value,
            status: status.value,
            stats,
            ...(hasStorage ? { storage } : {}),
        },
    };
};

const validateReportPolicyPayload = (value: unknown): Validation<HostPolicySnapshot> => {
    if (!isPlainObject(value) || !hasKeys(value, ['session_generation', 'generation', 'config'])) return failure('report policy fields invalid');
    if (!isInt(value.session_generation, 0, 4294967295) || !isInt(value.generation, 0, 4294967295)) return failure('report policy generations invalid');
    const config = value.config;
    if (!isPlainObject(config) || !hasKeys(config, ['mqtt_enabled', 'webhook_enabled', 'backlog_capacity'])) return failure('report policy config fields invalid');
    if (typeof config.mqtt_enabled !== 'boolean' || typeof config.webhook_enabled !== 'boolean') return failure('report policy flags invalid');
    if (!isInt(config.backlog_capacity, 0, 1000000)) return failure('report policy backlog_capacity out of range');
    return {
        ok: true,
        value: {
            sessionGeneration: value.session_generation,
            generation: value.generation,
            observedAtMs: Date.now(),
            config: { mqtt_enabled: config.mqtt_enabled, webhook_enabled: config.webhook_enabled, backlog_capacity: config.backlog_capacity },
        },
    };
};

const validateEnablePayload = (value: unknown): Validation<{ session_generation: number; value: boolean }> => {
    if (!isPlainObject(value) || !hasKeys(value, ['session_generation', 'value'])) return failure('enable fields invalid');
    if (!isInt(value.session_generation, 0, 4294967295)) return failure('enable session_generation invalid');
    if (typeof value.value !== 'boolean') return failure('enable value is not a boolean');
    return { ok: true, value: { session_generation: value.session_generation, value: value.value } };
};

const validateVideoPayload = (value: unknown): Validation<{ url: string; session_generation: number; expires_at_ms: number; grant_id: string }> => {
    if (!isPlainObject(value) || !hasKeys(value, ['url', 'session_generation', 'expires_at_ms', 'grant_id'])) return failure('video grant fields invalid');
    if (typeof value.url !== 'string' || value.url.length < 8 || value.url.length > 512) return failure('video grant url invalid');
    if (!/^wss?:\/\//.test(value.url)) return failure('video grant url is not a media websocket');
    if (!isInt(value.session_generation, 0, 4294967295)) return failure('video grant session_generation invalid');
    if (!isInt(value.expires_at_ms, 0, 8640000000000000)) return failure('video grant expiry invalid');
    if (typeof value.grant_id !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(value.grant_id)) return failure('video grant_id invalid');
    return {
        ok: true,
        value: {
            url: value.url,
            session_generation: value.session_generation,
            expires_at_ms: value.expires_at_ms,
            grant_id: value.grant_id,
        },
    };
};

const validateLiveEvent = (value: unknown): Validation<LineCountingEvent> => {
    if (!isPlainObject(value) || !hasKeys(value, ['sequence', 'timestamp_ms', 'track_id', 'direction', 'target_class'])) return failure('event fields invalid');
    if (!isInt(value.sequence, 0, 4294967295) || !isInt(value.timestamp_ms, 0, 8640000000000000) || !isInt(value.track_id, 0, 4294967295)) return failure('event counters invalid');
    if (value.direction !== 'in' && value.direction !== 'out') return failure('event direction invalid');
    if (!isString(value.target_class, 64)) return failure('event target_class invalid');
    return { ok: true, value: value as unknown as LineCountingEvent };
};

const validateLiveTrack = (value: unknown): Validation<LineTrack> => {
    if (!isPlainObject(value) || !hasKeys(value, ['track_id', 'points'])) return failure('track fields invalid');
    if (!isInt(value.track_id, 0, 4294967295)) return failure('track id invalid');
    if (!Array.isArray(value.points) || value.points.length === 0 || value.points.length > 64) return failure('track points unbounded');
    const points = [];
    for (const point of value.points) {
        const checked = validatePoint(point);
        if (!checked.ok) return checked;
        points.push(checked.value);
    }
    return { ok: true, value: { track_id: value.track_id, points } };
};

const validateLiveData = (value: unknown): Validation<{ server_now_ms: number; events: LineCountingEvent[] | null; tracks: LineTrack[] | null }> => {
    if (!isPlainObject(value)) return failure('live data is not an object');
    const hasEvents = Object.prototype.hasOwnProperty.call(value, 'events');
    const hasTracks = Object.prototype.hasOwnProperty.call(value, 'tracks');
    const expected = ['server_now_ms', hasEvents ? 'events' : '', hasTracks ? 'tracks' : ''].filter(Boolean);
    if (!hasKeys(value, expected)) return failure('live data fields do not match the v1 schema');
    if (!isInt(value.server_now_ms, 0, 8640000000000000)) return failure('live server_now_ms invalid');
    let events: LineCountingEvent[] | null = null;
    let tracks: LineTrack[] | null = null;
    if (hasEvents) {
        if (!Array.isArray(value.events) || value.events.length > 100) return failure('live events unbounded');
        events = [];
        for (const item of value.events) {
            const checked = validateLiveEvent(item);
            if (!checked.ok) return checked;
            events.push(checked.value);
        }
    }
    if (hasTracks) {
        if (!Array.isArray(value.tracks) || value.tracks.length > 100) return failure('live tracks unbounded');
        tracks = [];
        for (const item of value.tracks) {
            const checked = validateLiveTrack(item);
            if (!checked.ok) return checked;
            tracks.push(checked.value);
        }
    }
    return { ok: true, value: { server_now_ms: value.server_now_ms, events, tracks } };
};

const LIVE_EVENTS_WINDOW = 200;

const mergeLiveEvents = (current: LineCountingEvent[], incoming: LineCountingEvent[]): LineCountingEvent[] => {
    const seen = new Set(current.map((event) => event.sequence));
    const merged = [...current];
    for (const event of incoming) {
        if (seen.has(event.sequence)) continue;
        seen.add(event.sequence);
        merged.push(event);
    }
    merged.sort((left, right) => right.sequence - left.sequence);
    return merged.slice(0, LIVE_EVENTS_WINDOW);
};

const unavailable = <T>(reason: string): Capability<T> => ({ state: 'unavailable', reason });

const outcomeReason = (op: BridgeOp, outcome: RequestOutcome): string => {
    const suffix = outcome.reason ? `: ${outcome.reason}` : '';
    switch (outcome.outcome) {
        case 'UNAVAILABLE': return `Host reported ${op} unavailable${suffix}`;
        case 'REJECTED': return `Host rejected ${op}${suffix}`;
        case 'CONFLICT': return `Host reported a ${op} generation conflict${suffix}`;
        default: return `${op} outcome is unknown${suffix}`;
    }
};

export interface RuntimeControllerOptions {
    pollIntervalMs?: number;
}

export interface RuntimeController {
    capabilities: LineCrossingCapabilities;
    refresh: () => Promise<LineCrossingUiState>;
    dispose: () => void;
    getState: () => LineCrossingUiState;
}

export function createRuntimeController(session: BridgeSession, options: RuntimeControllerOptions = {}): RuntimeController {
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    const listeners = new Set<(state: LineCrossingUiState) => void>();
    let ui: LineCrossingUiState = {
        revision: 1,
        app: unavailable('Bridge session is not authorized'),
        configWrite: unavailable('Bridge session is not authorized'),
        businessEnable: unavailable('Bridge session is not authorized'),
        enableWrite: unavailable('Bridge session is not authorized'),
        stats: unavailable('Bridge session is not authorized'),
        events: unavailable('Bridge session is not authorized'),
        tracks: unavailable('Bridge session is not authorized'),
        statsReset: unavailable('Bridge session is not authorized'),
        hostPolicy: unavailable('Bridge session is not authorized'),
        hostPolicyWrite: unavailable('Bridge session is not authorized'),
        video: unavailable('Bridge session is not authorized'),
    };
    let ops: ReadonlySet<BridgeOp> = new Set();
    let grantExpiresAtMs = 0;
    let livePhase: 'idle' | 'active' | 'failed' = 'idle';
    let liveReason = 'Host has not granted live.subscribe';
    let lastStreamSeq = -1;
    let liveEvents: LineCountingEvent[] = [];
    let statsBase: LineCountingStats | null = null;
    let statsAppliedSeq = 0;
    let refreshInFlight = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let disposed = false;

    const emitPatch = (patch: Partial<LineCrossingUiState>) => {
        if (Object.keys(patch).length === 0) return;
        const next: LineCrossingUiState = { ...ui, ...patch, revision: ui.revision + 1 };
        if (JSON.stringify(next) === JSON.stringify(ui)) return;
        ui = next;
        for (const listener of [...listeners]) listener(ui);
    };

    const capabilityKeys = [
        'app', 'configWrite', 'businessEnable', 'enableWrite', 'stats', 'events', 'tracks',
        'statsReset', 'hostPolicy', 'hostPolicyWrite', 'video',
    ] as const;

    const allUnavailableWith = (reason: string): boolean => capabilityKeys.every((key) => {
        const capability = ui[key];
        return capability.state === 'unavailable' && (capability as { reason: string }).reason === reason;
    });

    const markAllUnavailable = (reason: string) => {
        if (allUnavailableWith(reason)) return;
        emitPatch({
            app: unavailable(reason),
            configWrite: unavailable(reason),
            businessEnable: unavailable(reason),
            enableWrite: unavailable(reason),
            stats: unavailable(reason),
            events: unavailable(reason),
            tracks: unavailable(reason),
            statsReset: unavailable(reason),
            hostPolicy: unavailable(reason),
            hostPolicyWrite: unavailable(reason),
            video: unavailable(reason),
        });
    };

    const onLiveEvent = (event: BridgeEvent) => {
        if (livePhase !== 'active') return;
        if (event.payload.status === 'REVOKE') {
            livePhase = 'failed';
            liveReason = 'Host revoked the live stream';
            emitPatch({ events: unavailable(liveReason), tracks: unavailable(liveReason) });
            return;
        }
        if (event.payload.status === 'GAP' || event.payload.status === 'STALE') {
            liveReason = 'Live stream is stale; awaiting the next frame';
            if (ui.events.state === 'available' || ui.tracks.state === 'available') {
                emitPatch({ events: { state: 'stale', reason: liveReason }, tracks: { state: 'stale', reason: liveReason } });
            }
            return;
        }
        lastStreamSeq = event.payload.stream_seq;
        const data = validateLiveData(event.payload.data);
        if (!data.ok) {
            livePhase = 'failed';
            liveReason = `Live event data failed validation: ${data.reason}`;
            emitPatch({ events: unavailable(liveReason), tracks: unavailable(liveReason) });
            return;
        }
        const patch: Partial<LineCountingUiState> = {};
        if (data.value.events !== null || ui.events.state === 'available') {
            liveEvents = data.value.events === null ? liveEvents : mergeLiveEvents(liveEvents, data.value.events);
            patch.events = { state: 'available', value: { events: liveEvents, server_now_ms: data.value.server_now_ms }, observedAtMs: Date.now() };
            if (data.value.events !== null && statsBase !== null) {
                const next = { window: { ...statsBase.window }, total: { ...statsBase.total } };
                for (const event of data.value.events) {
                    if (event.sequence <= statsAppliedSeq) continue;
                    if (event.direction === 'in') {
                        next.window.in += 1;
                        next.total.in += 1;
                    } else {
                        next.window.out += 1;
                        next.total.out += 1;
                    }
                    if (event.sequence > statsAppliedSeq) statsAppliedSeq = event.sequence;
                }
                statsBase = next;
                patch.stats = { state: 'available', value: next, observedAtMs: Date.now() };
            }
        }
        if (data.value.tracks !== null) {
            patch.tracks = { state: 'available', value: data.value.tracks, observedAtMs: Date.now() };
        }
        emitPatch(patch);
    };

    const activateLive = async () => {
        livePhase = 'idle';
        liveReason = 'Host has not granted live.subscribe';
        lastStreamSeq = -1;
        if (!ops.has('live.subscribe')) {
            emitPatch({ events: unavailable(liveReason), tracks: unavailable(liveReason) });
            return;
        }
        const result = await session.request('live.subscribe', { stream: 'live' });
        if (result.outcome !== 'APPLIED') {
            livePhase = 'failed';
            liveReason = outcomeReason('live.subscribe', result);
            emitPatch({ events: unavailable(liveReason), tracks: unavailable(liveReason) });
            return;
        }
        livePhase = 'active';
        liveReason = 'Live data has not been received yet';
        emitPatch({ events: unavailable(liveReason), tracks: unavailable(liveReason) });
    };

    const refresh = async (): Promise<LineCrossingUiState> => {
        if (disposed) return ui;
        const phase = session.getPhase();
        if (phase !== 'authorized') {
            markAllUnavailable('Bridge session is not authorized');
            return ui;
        }
        if (Date.now() >= grantExpiresAtMs) {
            markAllUnavailable('Bridge grant has expired');
            return ui;
        }
        if (refreshInFlight) return ui;
        refreshInFlight = true;
        try {
            const [snapshotResult, policyResult, enableResult] = await Promise.all([
                session.request('snapshot.read'),
                session.request('report-policy.read'),
                session.request('enable.read'),
            ]);
            const patch: Partial<LineCrossingUiState> = {};
            const now = Date.now();
            if (snapshotResult.outcome === 'APPLIED') {
                const payload = validateSnapshotPayload(adaptSnapshotV4(
                    snapshotResult.payload,
                    session.getIdentity()?.native_session_generation ?? 0));
                if (payload.ok) {
                    const snapshot: AppSnapshot = {
                        sessionGeneration: payload.value.session_generation,
                        configGeneration: payload.value.config_generation,
                        observedAtMs: now,
                        config: payload.value.config,
                        status: payload.value.status,
                        ...(payload.value.storage ? { storage: payload.value.storage } : {}),
                    };
                    patch.app = { state: 'available', value: snapshot, observedAtMs: now };
                    if (payload.value.stats !== null) {
                        statsBase = payload.value.stats;
                        statsAppliedSeq = liveEvents[0]?.sequence ?? 0;
                        patch.stats = { state: 'available', value: payload.value.stats, observedAtMs: now };
                    }
                    else patch.stats = unavailable('Host snapshot did not include statistics');
                } else {
                    patch.app = unavailable(`Host snapshot failed validation: ${payload.reason}`);
                    patch.stats = unavailable('Host snapshot failed validation');
                }
            } else {
                patch.app = unavailable(outcomeReason('snapshot.read', snapshotResult));
                patch.stats = unavailable(outcomeReason('snapshot.read', snapshotResult));
            }
            patch.configWrite = ops.has('config.apply') ? { state: 'available', value: true, observedAtMs: now } : unavailable('Host has not granted config.apply');
            patch.statsReset = ops.has('counters.reset') ? { state: 'available', value: true, observedAtMs: now } : unavailable('Host has not granted counters.reset');
            if (policyResult.outcome === 'APPLIED') {
                const payload = validateReportPolicyPayload(policyResult.payload);
                if (payload.ok) patch.hostPolicy = { state: 'available', value: payload.value, observedAtMs: now };
                else patch.hostPolicy = unavailable(`Host policy failed validation: ${payload.reason}`);
            } else {
                patch.hostPolicy = unavailable(outcomeReason('report-policy.read', policyResult));
            }
            patch.hostPolicyWrite = ops.has('report-policy.apply') ? { state: 'available', value: true, observedAtMs: now } : unavailable('Host has not granted report-policy.apply');
            if (enableResult.outcome === 'APPLIED') {
                const payload = validateEnablePayload(enableResult.payload);
                if (payload.ok) patch.businessEnable = { state: 'available', value: payload.value.value, observedAtMs: now };
                else patch.businessEnable = unavailable(`Enable state failed validation: ${payload.reason}`);
            } else {
                patch.businessEnable = unavailable(outcomeReason('enable.read', enableResult));
            }
            patch.enableWrite = ops.has('enable.apply') ? { state: 'available', value: true, observedAtMs: now } : unavailable('Host has not granted enable.apply');
            emitPatch(patch);
            return ui;
        } finally {
            refreshInFlight = false;
        }
    };

    const onNotification = (notification: BridgeNotification) => {
        if (notification.kind === 'grant') {
            adoptGrant(notification.grant);
            void (async () => {
                await activateLive();
                await refresh();
            })();
            return;
        }
        if (notification.kind === 'event') {
            onLiveEvent(notification.event);
            return;
        }
        if (notification.kind === 'hello') return;
        ops.clear();
        grantExpiresAtMs = 0;
        livePhase = 'idle';
        lastStreamSeq = -1;
        liveReason = notification.reason;
        markAllUnavailable(notification.reason);
    };

    const adoptGrant = (grant: BridgeGrant) => {
        ops = new Set(grant.ops);
        grantExpiresAtMs = grant.expires_at_ms;
        const identityCheck = validateIdentity(grant.identity);
        if (identityCheck.ok && identityCheck.value.app_id !== BRIDGE_APP_ID) {
            session.revoke('GRANT app_id does not match this signed App');
            return;
        }
    };

    const unsubscribeSession = session.subscribe(onNotification);

    if (pollIntervalMs > 0 && typeof setInterval === 'function') {
        pollTimer = setInterval(() => {
            if (session.getPhase() === 'authorized') void refresh();
        }, pollIntervalMs);
    }

    const requireAppSession = (): { sessionGeneration: number } | null => {
        const app = ui.app;
        return app.state === 'available' ? { sessionGeneration: app.value.sessionGeneration } : null;
    };

    const capabilities: LineCrossingCapabilities = {
        readState: () => refresh(),
        subscribe: (listener) => {
            listeners.add(listener);
            return () => listeners.delete(listener);
        },
        applyConfig: async (request) => {
            const app = requireAppSession();
            if (!app || app.sessionGeneration !== request.sessionGeneration) {
                return { outcome: 'UNAVAILABLE', reason: 'App snapshot unavailable for config write' };
            }
            const result = await session.request('config.apply', {
                session_generation: request.sessionGeneration,
                expected_config_generation: request.expectedConfigGeneration,
                candidate: request.candidate,
            });
            if (result.outcome !== 'APPLIED') return { outcome: result.outcome === 'REJECTED' ? 'UNAVAILABLE' : result.outcome, reason: outcomeReason('config.apply', result) };
            const payload = isPlainObject(result.payload) ? result.payload : null;
            const snapshot = payload
                ? validateSnapshotPayload(adaptSnapshotV4(
                    payload.snapshot,
                    session.getIdentity()?.native_session_generation ?? 0))
                : failure('config result has no snapshot');
            if (!payload
                || !snapshot.ok
                || !isInt(payload.session_generation, 0, 4294967295)
                || !isInt(payload.config_generation, 0, 4294967295)
                || payload.session_generation !== request.sessionGeneration
                || payload.config_generation <= request.expectedConfigGeneration
                || snapshot.value.session_generation !== request.sessionGeneration
                || snapshot.value.config_generation !== payload.config_generation) {
                return { outcome: 'UNKNOWN', reason: 'Bridge config result failed the generation cross-check' };
            }
            const appliedSnapshot: AppSnapshot = {
                sessionGeneration: snapshot.value.session_generation,
                configGeneration: snapshot.value.config_generation,
                observedAtMs: Date.now(),
                config: snapshot.value.config,
                status: snapshot.value.status,
                ...(snapshot.value.storage ? { storage: snapshot.value.storage } : {}),
            };
            emitPatch({
                app: { state: 'available', value: appliedSnapshot, observedAtMs: appliedSnapshot.observedAtMs },
            });
            return {
                outcome: 'APPLIED',
                sessionGeneration: payload.session_generation,
                configGeneration: payload.config_generation,
                snapshot: appliedSnapshot,
            };
        },
        applyHostPolicy: async (request) => {
            const app = requireAppSession();
            const host = ui.hostPolicy;
            if (!app || app.sessionGeneration !== request.sessionGeneration || host.state !== 'available' || host.value.generation !== request.expectedGeneration) {
                return { outcome: 'UNAVAILABLE', reason: 'Host policy snapshot unavailable for write' };
            }
            const result = await session.request('report-policy.apply', {
                session_generation: request.sessionGeneration,
                expected_generation: request.expectedGeneration,
                candidate: request.candidate,
            });
            if (result.outcome !== 'APPLIED') return { outcome: result.outcome === 'REJECTED' ? 'UNAVAILABLE' : result.outcome, reason: outcomeReason('report-policy.apply', result) };
            const payload = isPlainObject(result.payload) ? result.payload : null;
            const snapshot = payload ? validateReportPolicyPayload(payload.snapshot) : failure('policy result has no snapshot');
            if (!payload
                || !snapshot.ok
                || !isInt(payload.session_generation, 0, 4294967295)
                || !isInt(payload.generation, 0, 4294967295)
                || payload.session_generation !== request.sessionGeneration
                || payload.generation <= request.expectedGeneration
                || snapshot.value.sessionGeneration !== request.sessionGeneration
                || snapshot.value.generation !== payload.generation) {
                return { outcome: 'UNKNOWN', reason: 'Bridge policy result failed the generation cross-check' };
            }
            emitPatch({ hostPolicy: { state: 'available', value: snapshot.value, observedAtMs: snapshot.value.observedAtMs } });
            return {
                outcome: 'APPLIED',
                sessionGeneration: payload.session_generation,
                generation: payload.generation,
                snapshot: snapshot.value,
            };
        },
        setBusinessEnable: async (request) => {
            const app = requireAppSession();
            if (!app || app.sessionGeneration !== request.sessionGeneration) {
                return { outcome: 'UNAVAILABLE', reason: 'App snapshot unavailable for Enable write' };
            }
            const result = await session.request('enable.apply', {
                session_generation: request.sessionGeneration,
                value: request.value,
            });
            if (result.outcome !== 'APPLIED') return { outcome: result.outcome === 'REJECTED' ? 'UNAVAILABLE' : result.outcome, reason: outcomeReason('enable.apply', result) };
            const payload = validateEnablePayload(result.payload);
            if (!payload.ok
                || payload.value.session_generation !== request.sessionGeneration
                || payload.value.value !== request.value) {
                return { outcome: 'UNKNOWN', reason: 'Bridge Enable result failed the cross-check' };
            }
            const observedAtMs = Date.now();
            emitPatch({ businessEnable: { state: 'available', value: payload.value.value, observedAtMs } });
            const outcome: EnableApplyOutcome = { outcome: 'APPLIED', sessionGeneration: payload.value.session_generation, value: payload.value.value, observedAtMs };
            return outcome;
        },
        resetStats: async (request) => {
            const app = requireAppSession();
            if (!app || app.sessionGeneration !== request.sessionGeneration) {
                return { outcome: 'UNAVAILABLE', reason: 'App snapshot unavailable for counters reset' };
            }
            const result = await session.request('counters.reset', { session_generation: request.sessionGeneration });
            if (result.outcome !== 'APPLIED') return { outcome: result.outcome === 'REJECTED' ? 'UNAVAILABLE' : result.outcome, reason: outcomeReason('counters.reset', result) };
            const payload = isPlainObject(result.payload) ? result.payload : null;
            if (!payload || payload.session_generation !== request.sessionGeneration) {
                return { outcome: 'UNKNOWN', reason: 'Bridge reset result failed the session cross-check' };
            }
            await refresh();
            const outcome: ResetOutcome = { outcome: 'APPLIED', sessionGeneration: request.sessionGeneration };
            return outcome;
        },
        openVideoStream: async (request) => {
            const app = requireAppSession();
            if (!app || app.sessionGeneration !== request.sessionGeneration) {
                return unavailable('App snapshot unavailable for video open');
            }
            const result = await session.request('video.open', { session_generation: request.sessionGeneration });
            if (result.outcome !== 'APPLIED') return unavailable(outcomeReason('video.open', result));
            const payload = validateVideoPayload(result.payload);
            if (!payload.ok) return unavailable(`Video grant failed validation: ${payload.reason}`);
            if (payload.value.session_generation !== request.sessionGeneration || payload.value.expires_at_ms <= Date.now()) {
                return unavailable('Video grant failed the session or expiry cross-check');
            }
            let released = false;
            const grant: VideoStreamGrant = {
                url: payload.value.url,
                sessionGeneration: payload.value.session_generation,
                expiresAtMs: payload.value.expires_at_ms,
                release: () => {
                    if (released) return;
                    released = true;
                    const video = ui.video;
                    if (video.state === 'available' && video.value === grant) {
                        emitPatch({ video: unavailable('Video stream grant released') });
                    }
                    void session.request('video.close', {
                        session_generation: payload.value.session_generation,
                        grant_id: payload.value.grant_id,
                    });
                },
            };
            const granted: Capability<VideoStreamGrant> = { state: 'available', value: grant, observedAtMs: Date.now() };
            emitPatch({ video: granted });
            return granted;
        },
    };

    return {
        capabilities,
        refresh,
        dispose: () => {
            disposed = true;
            if (pollTimer !== null) clearInterval(pollTimer);
            pollTimer = null;
            unsubscribeSession();
            listeners.clear();
        },
        getState: () => ui,
    };
}

export function createRuntimeCapabilities(session: BridgeSession): LineCrossingCapabilities {
    return createRuntimeController(session).capabilities;
}
