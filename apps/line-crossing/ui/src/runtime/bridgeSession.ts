import {
    MAX_PENDING_REQUESTS,
    REQUEST_DEADLINE_MS,
    validateEvent,
    validateGrant,
    validateHello,
    validateResult,
    validateRevoke,
    withinMessageLimit,
    type BridgeEvent,
    type BridgeGrant,
    type BridgeHello,
    type BridgeIdentity,
    type BridgeOp,
    type BridgeOutcome,
    type BridgeRequest,
} from './bridgeProtocol';

export type BridgePhase = 'awaiting-hello' | 'awaiting-grant' | 'authorized' | 'revoked';

export interface PortLike {
    postMessage: (data: unknown) => void;
    close?: () => void;
    start?: () => void;
    addEventListener: (type: 'message', listener: (event: { data: unknown }) => void) => void;
    removeEventListener?: (type: 'message', listener: (event: { data: unknown }) => void) => void;
}

export type BridgeNotification =
    | { kind: 'hello'; grantId: string }
    | { kind: 'grant'; grant: BridgeGrant }
    | { kind: 'event'; event: BridgeEvent }
    | { kind: 'revoked'; reason: string };

export interface RequestOutcome {
    outcome: BridgeOutcome;
    payload?: unknown;
    reason?: string;
}

export interface BridgeSessionOptions {
    deadlineMs?: number;
    setTimeoutFn?: (handler: () => void, timeout: number) => unknown;
    clearTimeoutFn?: (handle: unknown) => void;
}

interface PendingRequest {
    op: BridgeOp;
    resolve: (outcome: RequestOutcome) => void;
}

const sameIdentity = (a: BridgeIdentity, b: BridgeIdentity): boolean =>
    JSON.stringify(a) === JSON.stringify(b);

export class BridgeSession {
    private phase: BridgePhase = 'awaiting-hello';
    private grant: BridgeGrant | null = null;
    private identity: BridgeIdentity | null = null;
    private grantId: string | null = null;
    private port: PortLike | null = null;
    private portListener: ((event: { data: unknown }) => void) | null = null;
    private lastInboundSeq = -1;
    private outboundSeq = 0;
    private outboundRequestId = 0;
    private readonly pending = new Map<number, PendingRequest>();
    private readonly listeners = new Set<(notification: BridgeNotification) => void>();
    private readonly deadlineMs: number;
    private readonly setTimeoutFn: (handler: () => void, timeout: number) => unknown;
    private readonly clearTimeoutFn: (handle: unknown) => void;
    private droppedInbound = 0;

    constructor(options: BridgeSessionOptions = {}) {
        this.deadlineMs = options.deadlineMs ?? REQUEST_DEADLINE_MS;
        this.setTimeoutFn = options.setTimeoutFn ?? ((handler, timeout) => setTimeout(handler, timeout));
        this.clearTimeoutFn = options.clearTimeoutFn ?? ((handle) => clearTimeout(handle as ReturnType<typeof setTimeout>));
    }

    getPhase(): BridgePhase {
        return this.phase;
    }

    getGrant(): BridgeGrant | null {
        return this.grant;
    }

    getIdentity(): BridgeIdentity | null {
        return this.identity;
    }

    getDroppedInboundCount(): number {
        return this.droppedInbound;
    }

    subscribe(listener: (notification: BridgeNotification) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    acceptHello(hello: unknown, port: PortLike): boolean {
        if (this.phase !== 'awaiting-hello') {
            this.droppedInbound += 1;
            return false;
        }
        const check = validateHello(hello);
        if (!check.ok) {
            this.droppedInbound += 1;
            return false;
        }
        const message: BridgeHello = check.value;
        this.identity = message.identity;
        this.grantId = message.grant_id;
        this.port = port;
        this.portListener = (event: { data: unknown }) => this.handlePortData(event.data);
        port.addEventListener('message', this.portListener);
        port.start?.();
        this.phase = 'awaiting-grant';
        this.notify({ kind: 'hello', grantId: message.grant_id });
        return true;
    }

    request(op: BridgeOp, payload: Record<string, unknown> = {}): Promise<RequestOutcome> {
        if (this.phase !== 'authorized') {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: 'Bridge session is not authorized' });
        }
        const grant = this.grant;
        if (!grant || !this.identity || !this.grantId) {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: 'Bridge session has no active grant' });
        }
        if (!grant.ops.includes(op)) {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: `Host has not granted ${op}` });
        }
        if (this.pending.size >= MAX_PENDING_REQUESTS) {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: 'Bridge pending request limit reached' });
        }
        const requestId = this.outboundRequestId + 1;
        const seq = this.outboundSeq + 1;
        const message: BridgeRequest = {
            protocol: 'ne301.sidecar.bridge.v1',
            type: 'REQUEST',
            seq,
            grant_id: this.grantId,
            identity: this.identity,
            request_id: requestId,
            op,
            payload,
        };
        if (!withinMessageLimit(message)) {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: 'Bridge request exceeds the message size limit' });
        }
        this.outboundRequestId = requestId;
        this.outboundSeq = seq;
        const port = this.port;
        if (!port) {
            return Promise.resolve({ outcome: 'UNAVAILABLE', reason: 'Bridge transport is not connected' });
        }
        return new Promise<RequestOutcome>((resolve) => {
            let settled = false;
            const finish = (outcome: RequestOutcome) => {
                if (settled) return;
                settled = true;
                this.clearTimeoutFn(timer);
                resolve(outcome);
            };
            const timer = this.setTimeoutFn(() => {
                if (this.pending.get(requestId)) this.pending.delete(requestId);
                finish({ outcome: 'UNKNOWN', reason: 'Bridge request timed out before a RESULT arrived' });
            }, this.deadlineMs);
            this.pending.set(requestId, { op, resolve: finish });
            port.postMessage(message);
        });
    }

    revoke(reason: string): void {
        if (this.phase === 'revoked') return;
        this.phase = 'revoked';
        this.flushPending('Bridge session revoked');
        this.closePort();
        this.notify({ kind: 'revoked', reason });
    }

    dispose(reason: string): void {
        this.revoke(reason);
        this.listeners.clear();
    }

    private flushPending(reason: string): void {
        for (const pending of this.pending.values()) pending.resolve({ outcome: 'UNAVAILABLE', reason });
        this.pending.clear();
    }

    private closePort(): void {
        if (this.port && this.portListener) this.port.removeEventListener?.('message', this.portListener);
        this.port?.close?.();
        this.port = null;
        this.portListener = null;
    }

    private notify(notification: BridgeNotification): void {
        for (const listener of [...this.listeners]) listener(notification);
    }

    private handlePortData(data: unknown): void {
        if (this.phase !== 'awaiting-grant' && this.phase !== 'authorized') {
            this.droppedInbound += 1;
            return;
        }
        if (!withinMessageLimit(data)) {
            this.revoke('Bridge message exceeds the 16 KiB size limit');
            return;
        }
        if (typeof data !== 'object' || data === null) {
            this.droppedInbound += 1;
            return;
        }
        const probe = data as Record<string, unknown>;
        switch (probe.type) {
            case 'GRANT': return this.handleGrant(data);
            case 'RESULT': return this.handleResult(data);
            case 'EVENT': return this.handleEvent(data);
            case 'REVOKE': return this.handleRevoke(data);
            default:
                this.droppedInbound += 1;
        }
    }

    private consumeSeq(seq: number): boolean {
        if (seq <= this.lastInboundSeq) {
            this.droppedInbound += 1;
            return false;
        }
        this.lastInboundSeq = seq;
        return true;
    }

    private matchesSession(grantId: string, identity: BridgeIdentity): boolean {
        return grantId === this.grantId && this.identity !== null && sameIdentity(identity, this.identity);
    }

    private handleGrant(data: unknown): void {
        const check = validateGrant(data);
        if (!check.ok) {
            this.revoke(`Malformed GRANT: ${check.reason}`);
            return;
        }
        const grant = check.value;
        if (!this.consumeSeq(grant.seq)) return;
        if (!this.matchesSession(grant.grant_id, grant.identity)) {
            this.revoke('GRANT identity does not match the session handshake');
            return;
        }
        if (this.phase === 'revoked') return;
        this.grant = grant;
        this.phase = 'authorized';
        this.notify({ kind: 'grant', grant });
    }

    private handleResult(data: unknown): void {
        const check = validateResult(data);
        if (!check.ok) {
            this.revoke(`Malformed RESULT: ${check.reason}`);
            return;
        }
        const result = check.value;
        if (!this.consumeSeq(result.seq)) return;
        if (!this.matchesSession(result.grant_id, result.identity)) {
            this.revoke('RESULT identity does not match the session handshake');
            return;
        }
        const pending = this.pending.get(result.request_id);
        if (!pending || pending.op !== result.op) {
            this.droppedInbound += 1;
            return;
        }
        this.pending.delete(result.request_id);
        const payload = result.payload as { reason?: unknown } | undefined;
        pending.resolve({
            outcome: result.outcome,
            payload: result.payload,
            reason: typeof payload?.reason === 'string' ? payload.reason : undefined,
        });
    }

    private handleEvent(data: unknown): void {
        const check = validateEvent(data);
        if (!check.ok) {
            this.revoke(`Malformed EVENT: ${check.reason}`);
            return;
        }
        const event = check.value;
        if (!this.consumeSeq(event.seq)) return;
        if (!this.matchesSession(event.grant_id, event.identity)) {
            this.revoke('EVENT identity does not match the session handshake');
            return;
        }
        if (this.phase !== 'authorized') {
            this.droppedInbound += 1;
            return;
        }
        this.notify({ kind: 'event', event });
    }

    private handleRevoke(data: unknown): void {
        const check = validateRevoke(data);
        if (!check.ok) {
            this.revoke('Malformed REVOKE received');
            return;
        }
        const message = check.value;
        if (!this.consumeSeq(message.seq)) return;
        if (!this.matchesSession(message.grant_id, message.identity)) {
            this.revoke('REVOKE identity does not match the session handshake');
            return;
        }
        this.revoke(message.reason);
    }
}
