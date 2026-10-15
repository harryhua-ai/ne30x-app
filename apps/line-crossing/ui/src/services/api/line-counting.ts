export type LineCountingState = 'running' | 'stopped' | 'unknown';

export interface LineCountingLine {
    x1: number;
    y1: number;
    x2: number;
    y2: number;
    outside_x: number;
    outside_y: number;
}

export interface LineCountingTracking {
    association_distance: number;
    history_length: number;
    max_missed_frames: number;
    confirmation_frames: number;
}

export interface LineCountingReporting {
    tracks_enabled: boolean;
    heat_grid_enabled: boolean;
}

export interface LineCountingConfig {
    counter_name: string;
    target_class: string;
    line: LineCountingLine;
    confidence_threshold: number;
    tracking: LineCountingTracking;
    window_minutes: number;
    reporting: LineCountingReporting;
}

export interface LineCountingModelClass {
    id: number;
    name: string;
}

export interface LineCountingModel {
    name: string;
    version: string;
    postprocess_type: string;
    generation: number;
    classes: LineCountingModelClass[];
}

export interface LineCountingStatus {
    state: LineCountingState;
    target_class: string;
    model: LineCountingModel;
}

export interface LineCountingStats {
    window: { in: number; out: number };
    total: { in: number; out: number };
}

export interface LineCountingEvent {
    sequence: number;
    timestamp_ms: number;
    track_id: number;
    direction: 'in' | 'out';
    target_class?: string;
}

export interface LineCountingEvents {
    events: LineCountingEvent[];
    server_now_ms: number;
}

export interface LineTrack {
    track_id: number;
    points: Array<{ x: number; y: number }>;
}

export interface LineCrossingConfigCandidate {
    schema: 1;
    counter_name: string;
    target_class_name: string;
    line: LineCountingLine;
    conf_threshold_permille: number;
    max_dist_permille: number;
    track_history_k: number;
    max_miss: number;
    k_confirm: number;
    tracks_report_enable: boolean;
    heat_grid_enable: boolean;
    window_minutes: number;
}

export interface AppSnapshot {
    sessionGeneration: number;
    configGeneration: number;
    observedAtMs: number;
    config: LineCrossingConfigCandidate;
    status: LineCountingStatus;
}

export interface HostPolicyConfig {
    mqtt_enabled: boolean;
    webhook_enabled: boolean;
    backlog_capacity: number;
}

export interface HostPolicySnapshot {
    sessionGeneration: number;
    generation: number;
    observedAtMs: number;
    config: HostPolicyConfig;
}

export type Capability<T> =
    | { state: 'available'; value: T; observedAtMs: number }
    | { state: 'unavailable'; reason: string }
    | { state: 'stale'; reason: string };

export interface VideoStreamGrant {
    url: string;
    sessionGeneration: number;
    expiresAtMs: number;
    release: () => void;
}

export interface LineCrossingUiState {
    revision: number;
    app: Capability<AppSnapshot>;
    configWrite: Capability<boolean>;
    businessEnable: Capability<boolean>;
    enableWrite: Capability<boolean>;
    stats: Capability<LineCountingStats>;
    events: Capability<LineCountingEvents>;
    tracks: Capability<LineTrack[]>;
    statsReset: Capability<boolean>;
    hostPolicy: Capability<HostPolicySnapshot>;
    hostPolicyWrite: Capability<boolean>;
    video: Capability<VideoStreamGrant>;
}

export type ApplyOutcome =
    | { outcome: 'APPLIED'; sessionGeneration: number; configGeneration: number; snapshot: AppSnapshot }
    | { outcome: 'CONFLICT' | 'UNKNOWN' | 'UNAVAILABLE'; reason?: string };

export type HostApplyOutcome =
    | { outcome: 'APPLIED'; sessionGeneration: number; generation: number; snapshot: HostPolicySnapshot }
    | { outcome: 'CONFLICT' | 'UNKNOWN' | 'UNAVAILABLE'; reason?: string };

export type EnableApplyOutcome =
    | { outcome: 'APPLIED'; sessionGeneration: number; value: boolean; observedAtMs: number }
    | { outcome: 'CONFLICT' | 'UNKNOWN' | 'UNAVAILABLE'; reason?: string };

export type ResetOutcome =
    | { outcome: 'APPLIED'; sessionGeneration: number }
    | { outcome: 'CONFLICT' | 'UNKNOWN' | 'UNAVAILABLE'; reason?: string };

export interface LineCrossingCapabilities {
    readState: () => Promise<LineCrossingUiState>;
    subscribe: (listener: (state: LineCrossingUiState) => void) => () => void;
    applyConfig: (request: {
        sessionGeneration: number;
        expectedConfigGeneration: number;
        candidate: LineCrossingConfigCandidate;
    }) => Promise<ApplyOutcome>;
    applyHostPolicy: (request: {
        sessionGeneration: number;
        expectedGeneration: number;
        candidate: HostPolicyConfig;
    }) => Promise<HostApplyOutcome>;
    setBusinessEnable?: (request: { sessionGeneration: number; value: boolean }) => Promise<EnableApplyOutcome>;
    resetStats: (request: { sessionGeneration: number }) => Promise<ResetOutcome>;
    openVideoStream: (request: { sessionGeneration: number }) => Promise<Capability<VideoStreamGrant>>;
}

export const normToPm = (value: number) => Math.round(value * 1000);

export function candidateToUiConfig(candidate: LineCrossingConfigCandidate): LineCountingConfig {
    return {
        counter_name: candidate.counter_name,
        target_class: candidate.target_class_name,
        line: { ...candidate.line },
        confidence_threshold: candidate.conf_threshold_permille / 1000,
        tracking: {
            association_distance: candidate.max_dist_permille / 1000,
            history_length: candidate.track_history_k,
            max_missed_frames: candidate.max_miss,
            confirmation_frames: candidate.k_confirm,
        },
        window_minutes: candidate.window_minutes,
        reporting: {
            tracks_enabled: candidate.tracks_report_enable,
            heat_grid_enabled: candidate.heat_grid_enable,
        },
    };
}

export function uiConfigToCandidate(config: LineCountingConfig): LineCrossingConfigCandidate {
    return {
        schema: 1,
        counter_name: config.counter_name,
        target_class_name: config.target_class,
        line: { ...config.line },
        conf_threshold_permille: normToPm(config.confidence_threshold),
        max_dist_permille: normToPm(config.tracking.association_distance),
        track_history_k: config.tracking.history_length,
        max_miss: config.tracking.max_missed_frames,
        k_confirm: config.tracking.confirmation_frames,
        tracks_report_enable: config.reporting.tracks_enabled,
        heat_grid_enable: config.reporting.heat_grid_enabled,
        window_minutes: config.window_minutes,
    };
}

const unavailable = <T>(reason: string): Capability<T> => ({ state: 'unavailable', reason });

export const unavailableCapabilities: LineCrossingCapabilities = {
    readState: async () => ({
        revision: 0,
        app: unavailable('Host App snapshot capability is unavailable'),
        configWrite: unavailable('App configuration capability is unavailable'),
        businessEnable: unavailable('Business Enable capability is unavailable'),
        enableWrite: unavailable('Business Enable control capability is unavailable'),
        stats: unavailable('Statistics capability is unavailable'),
        events: unavailable('Event capability is unavailable'),
        tracks: unavailable('Track capability is unavailable'),
        statsReset: unavailable('Statistics reset capability is unavailable'),
        hostPolicy: unavailable('Host policy capability is unavailable'),
        hostPolicyWrite: unavailable('Host policy write capability is unavailable'),
        video: unavailable('Video stream grant capability is unavailable'),
    }),
    subscribe: () => () => undefined,
    applyConfig: async () => ({ outcome: 'UNAVAILABLE', reason: 'App configuration capability is unavailable' }),
    applyHostPolicy: async () => ({ outcome: 'UNAVAILABLE', reason: 'Host policy write capability is unavailable' }),
    resetStats: async () => ({ outcome: 'UNAVAILABLE', reason: 'Statistics reset capability is unavailable' }),
    openVideoStream: async () => unavailable('Video stream grant capability is unavailable'),
};
