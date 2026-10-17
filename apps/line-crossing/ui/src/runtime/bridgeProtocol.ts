export const BRIDGE_PROTOCOL = 'ne301.sidecar.bridge.v1';
export const BRIDGE_CHANNEL = 'ne301.sidecar.bridge.v1';
export const BRIDGE_APP_ID = 'line-crossing';

export type BridgeMessageType = 'HELLO' | 'GRANT' | 'REQUEST' | 'RESULT' | 'EVENT' | 'REVOKE';

export const BRIDGE_OPS = [
    'snapshot.read',
    'config.read',
    'config.apply',
    'counters.reset',
    'report-policy.read',
    'report-policy.apply',
    'video.open',
    'video.close',
    'enable.read',
    'enable.apply',
    'live.subscribe',
    'live.unsubscribe',
] as const;

export type BridgeOp = (typeof BRIDGE_OPS)[number];

export type BridgeOutcome = 'APPLIED' | 'CONFLICT' | 'UNKNOWN' | 'REJECTED' | 'UNAVAILABLE';

export const BRIDGE_OUTCOMES: readonly BridgeOutcome[] = ['APPLIED', 'CONFLICT', 'UNKNOWN', 'REJECTED', 'UNAVAILABLE'];

export const MAX_MESSAGE_BYTES = 16384;
export const MAX_PENDING_REQUESTS = 4;
export const REQUEST_DEADLINE_MS = 10000;

export interface BridgeIdentity {
    publisher_id: string;
    app_id: string;
    publisher_key_sha256: string;
    native_tbs_sha256: string;
    ui_tbs_sha256: string;
    build_id: string;
    host_boot_generation: number;
    native_session_generation: number;
    ui_generation: number;
    sidecar_service_generation: number;
}

export interface BridgeHello {
    protocol: string;
    type: 'HELLO';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    channel: string;
}

export interface BridgeGrant {
    protocol: string;
    type: 'GRANT';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    expires_at_ms: number;
    ops: BridgeOp[];
}

export interface BridgeRequest {
    protocol: string;
    type: 'REQUEST';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    request_id: number;
    op: BridgeOp;
    payload: Record<string, unknown>;
}

export interface BridgeResult {
    protocol: string;
    type: 'RESULT';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    request_id: number;
    op: BridgeOp;
    outcome: BridgeOutcome;
    payload: unknown;
}

export type BridgeStreamStatus = 'GAP' | 'STALE' | 'REVOKE';

export interface BridgeEvent {
    protocol: string;
    type: 'EVENT';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    payload: {
        stream: string;
        stream_seq: number;
        status?: BridgeStreamStatus;
        data?: unknown;
    };
}

export interface BridgeRevoke {
    protocol: string;
    type: 'REVOKE';
    seq: number;
    grant_id: string;
    identity: BridgeIdentity;
    reason: string;
}

export type BridgeInboundMessage = BridgeGrant | BridgeResult | BridgeEvent | BridgeRevoke;

export type ValidationFailure = { ok: false; reason: string };
export type ValidationResult<T> = { ok: true; value: T } | ValidationFailure;

export const fail = (reason: string): ValidationFailure => ({ ok: false, reason });

const HEX64 = /^[0-9a-f]{64}$/;
const GRANT_ID = /^[A-Za-z0-9_-]{16,128}$/;
const MAX_STRING = 512;
const MAX_ARRAY = 256;
const MAX_DEPTH = 12;
const MAX_NODES = 4096;
const MAX_U32 = 4294967295;

export function isPlainObject(value: unknown): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
}

export const isSeq = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_U32;

const isFiniteYear = (value: unknown): value is number =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 8640000000000000;

const isBoundedString = (value: unknown, max: number = MAX_STRING): value is string =>
    typeof value === 'string' && value.length >= 1 && value.length <= max && /^[\x20-\x7e]*$/.test(value);

const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
    if (Object.keys(value).length !== keys.length) return false;
    return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
};

export function validateIdentity(value: unknown): ValidationResult<BridgeIdentity> {
    if (!isPlainObject(value)) return fail('identity is not an object');
    if (!exactKeys(value, [
        'publisher_id', 'app_id', 'publisher_key_sha256', 'native_tbs_sha256', 'ui_tbs_sha256',
        'build_id', 'host_boot_generation', 'native_session_generation', 'ui_generation',
        'sidecar_service_generation',
    ])) return fail('identity fields do not match the v1 schema');
    for (const key of ['publisher_id', 'app_id', 'build_id'] as const) {
        if (!isBoundedString(value[key], 128)) return fail(`identity.${key} is not a bounded string`);
    }
    for (const key of ['publisher_key_sha256', 'native_tbs_sha256', 'ui_tbs_sha256'] as const) {
        if (typeof value[key] !== 'string' || !HEX64.test(value[key])) return fail(`identity.${key} is not a sha256 digest`);
    }
    for (const key of [
        'host_boot_generation', 'native_session_generation', 'ui_generation', 'sidecar_service_generation',
    ] as const) {
        if (!isSeq(value[key])) return fail(`identity.${key} is not a generation counter`);
    }
    return { ok: true, value: value as unknown as BridgeIdentity };
}

const envelopeBase = (value: Record<string, unknown>, type: BridgeMessageType, keys: readonly string[]): ValidationFailure | null => {
    if (!exactKeys(value, ['protocol', 'type', 'seq', 'grant_id', 'identity', ...keys])) return fail('envelope fields do not match the v1 schema');
    if (value.protocol !== BRIDGE_PROTOCOL) return fail('unknown bridge protocol');
    if (value.type !== type) return fail('unexpected message type');
    if (!isSeq(value.seq)) return fail('seq is not a u32 counter');
    if (typeof value.grant_id !== 'string' || !GRANT_ID.test(value.grant_id)) return fail('grant_id is not an unguessable token');
    if (validateIdentity(value.identity).ok === false) return fail('identity failed validation');
    return null;
};

export function validateHello(value: unknown): ValidationResult<BridgeHello> {
    if (!isPlainObject(value)) return fail('HELLO is not an object');
    const base = envelopeBase(value, 'HELLO', ['channel']);
    if (base) return base;
    if (value.channel !== BRIDGE_CHANNEL) return fail('HELLO channel mismatch');
    return { ok: true, value: value as unknown as BridgeHello };
}

export function isBridgeOp(value: unknown): value is BridgeOp {
    return typeof value === 'string' && (BRIDGE_OPS as readonly string[]).includes(value);
}

export function validateGrant(value: unknown): ValidationResult<BridgeGrant> {
    if (!isPlainObject(value)) return fail('GRANT is not an object');
    const base = envelopeBase(value, 'GRANT', ['expires_at_ms', 'ops']);
    if (base) return base;
    if (!isFiniteYear(value.expires_at_ms)) return fail('GRANT expires_at_ms is not a timestamp');
    if (!Array.isArray(value.ops) || value.ops.length === 0 || value.ops.length > BRIDGE_OPS.length) return fail('GRANT ops whitelist is not bounded');
    const seen = new Set<string>();
    for (const op of value.ops) {
        if (!isBridgeOp(op)) return fail('GRANT ops contain an unknown op');
        if (seen.has(op)) return fail('GRANT ops contain duplicates');
        seen.add(op);
    }
    return { ok: true, value: value as unknown as BridgeGrant };
}

export function validateResult(value: unknown): ValidationResult<BridgeResult> {
    if (!isPlainObject(value)) return fail('RESULT is not an object');
    const base = envelopeBase(value, 'RESULT', ['request_id', 'op', 'outcome', 'payload']);
    if (base) return base;
    if (!isSeq(value.request_id)) return fail('RESULT request_id is not a u32');
    if (!isBridgeOp(value.op)) return fail('RESULT op is unknown');
    if (typeof value.outcome !== 'string' || !BRIDGE_OUTCOMES.includes(value.outcome as BridgeOutcome)) return fail('RESULT outcome is unknown');
    if (value.payload !== undefined && !isPlainObject(value.payload)) return fail('RESULT payload is not a plain object');
    return { ok: true, value: value as unknown as BridgeResult };
}

export function validateEvent(value: unknown): ValidationResult<BridgeEvent> {
    if (!isPlainObject(value)) return fail('EVENT is not an object');
    const base = envelopeBase(value, 'EVENT', ['payload']);
    if (base) return base;
    const payload = value.payload;
    if (!isPlainObject(payload)) return fail('EVENT payload is not an object');
    if (!exactKeys(payload, ['stream', 'stream_seq', 'status', 'data'])
        && !exactKeys(payload, ['stream', 'stream_seq', 'status'])
        && !exactKeys(payload, ['stream', 'stream_seq', 'data'])
        && !exactKeys(payload, ['stream', 'stream_seq'])) return fail('EVENT payload fields do not match the v1 schema');
    if (!isBoundedString(payload.stream, 64)) return fail('EVENT stream is not a bounded string');
    if (!isSeq(payload.stream_seq)) return fail('EVENT stream_seq is not a u32');
    if (payload.status !== undefined && (typeof payload.status !== 'string' || !['GAP', 'STALE', 'REVOKE'].includes(payload.status))) return fail('EVENT status is unknown');
    if (payload.data !== undefined && !isPlainObject(payload.data)) return fail('EVENT data is not a plain object');
    return { ok: true, value: value as unknown as BridgeEvent };
}

export function validateRevoke(value: unknown): ValidationResult<BridgeRevoke> {
    if (!isPlainObject(value)) return fail('REVOKE is not an object');
    const base = envelopeBase(value, 'REVOKE', ['reason']);
    if (base) return base;
    if (!isBoundedString(value.reason, 256)) return fail('REVOKE reason is not a bounded string');
    return { ok: true, value: value as unknown as BridgeRevoke };
}

const utf8ByteLength = (value: string): number => {
    let bytes = 0;
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code < 0x80) bytes += 1;
        else if (code < 0x800) bytes += 2;
        else if (code >= 0xd800 && code <= 0xdbff) {
            bytes += 4;
            index += 1;
        } else bytes += 3;
    }
    return bytes;
};

export function encodedByteSize(value: unknown, depth: number = 0, counter: { nodes: number } = { nodes: 0 }): number {
    if (depth > MAX_DEPTH || counter.nodes > MAX_NODES) return Number.MAX_SAFE_INTEGER;
    counter.nodes += 1;
    if (value === null) return 4;
    switch (typeof value) {
        case 'string':
            return utf8ByteLength(value) + 2;
        case 'number':
            return 9;
        case 'boolean':
            return 5;
        case 'object':
            break;
        default:
            return Number.MAX_SAFE_INTEGER;
    }
    let total = 2;
    if (Array.isArray(value)) {
        if (value.length > MAX_ARRAY) return Number.MAX_SAFE_INTEGER;
        for (const item of value) {
            total += encodedByteSize(item, depth + 1, counter) + 1;
            if (total > MAX_MESSAGE_BYTES) return total;
        }
        return total;
    }
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_ARRAY) return Number.MAX_SAFE_INTEGER;
    for (const [key, item] of entries) {
        total += utf8ByteLength(key) + encodedByteSize(item, depth + 1, counter) + 2;
        if (total > MAX_MESSAGE_BYTES) return total;
    }
    return total;
}

export function withinMessageLimit(value: unknown, limit: number = MAX_MESSAGE_BYTES): boolean {
    return encodedByteSize(value, 0, { nodes: 0 }) <= limit;
}
