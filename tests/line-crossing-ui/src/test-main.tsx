import { render } from 'preact';
import { I18nProvider } from '@lingui/react';
import { Toaster } from 'sonner';
import LineCountingModule from '../../../apps/line-crossing/ui/src/LineCountingModule';
import { i18n } from '../../../apps/line-crossing/ui/src/i18n';
import { BridgeSession, type PortLike } from '../../../apps/line-crossing/ui/src/runtime/bridgeSession';
import { createRuntimeController } from '../../../apps/line-crossing/ui/src/runtime/runtimeCapabilities';
import { BRIDGE_PROTOCOL } from '../../../apps/line-crossing/ui/src/runtime/bridgeProtocol';
import { createTestCapabilities } from './test-capabilities';
import '../../../apps/line-crossing/ui/src/styles/index.css';

const params = new URLSearchParams(window.location.search);

if (params.get('scenario') === 'runtime') {
    const identity = {
        publisher_id: 'test-publisher',
        app_id: 'line-crossing',
        publisher_key_sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        native_tbs_sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        ui_tbs_sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        build_id: 'fixture-build',
        host_boot_generation: 3,
        native_session_generation: 7,
        ui_generation: 1,
        sidecar_service_generation: 2,
    };
    const sessionGeneration = 7;
    const candidate = {
        schema: 1,
        counter_name: 'Counter Runtime',
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
    const received: Array<Record<string, unknown>> = [];
    let outboundSeq = 0;
    const nextSeq = () => { outboundSeq += 1; return outboundSeq; };
    const grantId = 'runtime-fixture-grant-0001';
    let portEmit: ((data: unknown) => void) | null = null;
    const port: PortLike = {
        postMessage: (data: unknown) => {
            if (typeof data !== 'object' || data === null) return;
            const message = data as Record<string, unknown>;
            if (message.type !== 'REQUEST') return;
            received.push(JSON.parse(JSON.stringify(message)));
            const op = message.op as string;
            const respond = (outcome: string, payload: Record<string, unknown>) => {
                portEmit?.({
                    protocol: BRIDGE_PROTOCOL,
                    type: 'RESULT',
                    seq: nextSeq(),
                    grant_id: grantId,
                    identity,
                    request_id: message.request_id,
                    op,
                    outcome,
                    payload,
                });
            };
            if (op === 'snapshot.read') {
                respond('APPLIED', {
                    session_generation: sessionGeneration,
                    config_generation: 12,
                    config: candidate,
                    status: {
                        state: 'running',
                        target_class: 'person',
                        model: {
                            name: 'Runtime Fixture Model',
                            version: 'fixture',
                            postprocess_type: 'yolo',
                            generation: 3,
                            classes: [{ id: 0, name: 'person' }],
                        },
                    },
                    stats: { window: { in: 5, out: 2 }, total: { in: 50, out: 20 } },
                });
                return;
            }
            if (op === 'report-policy.read') {
                respond('APPLIED', {
                    session_generation: sessionGeneration,
                    generation: 4,
                    config: { mqtt_enabled: false, webhook_enabled: true, backlog_capacity: 4 },
                });
                return;
            }
            if (op === 'enable.read') {
                respond('APPLIED', { session_generation: sessionGeneration, value: false });
                return;
            }
            if (op === 'video.open') {
                respond('APPLIED', {
                    url: 'ws://127.0.0.1:1/stream?grant=runtime-fixture',
                    session_generation: sessionGeneration,
                    expires_at_ms: Date.now() + 120000,
                    grant_id: 'runtimefixturegrant01',
                });
                return;
            }
            if (op === 'video.close') {
                respond('APPLIED', { session_generation: sessionGeneration });
                return;
            }
            if (op === 'live.subscribe') {
                respond('APPLIED', {});
                return;
            }
            respond('REJECTED', { reason: `runtime fixture does not implement ${op}` });
        },
        addEventListener: (_type: 'message', listener: (event: { data: unknown }) => void) => {
            portEmit = (data: unknown) => listener({ data });
        },
        removeEventListener: () => { portEmit = null; },
        start: () => undefined,
    };
    let streamSeq = 0;
    const emitLive = (events: Array<Record<string, unknown>>) => {
        streamSeq += 1;
        portEmit?.({
            protocol: BRIDGE_PROTOCOL,
            type: 'EVENT',
            seq: nextSeq(),
            grant_id: grantId,
            identity,
            payload: { stream: 'live', stream_seq: streamSeq, data: { server_now_ms: Date.now(), events } },
        });
    };
    const session = new BridgeSession();
    session.acceptHello({
        protocol: BRIDGE_PROTOCOL,
        type: 'HELLO',
        seq: nextSeq(),
        grant_id: grantId,
        identity,
        channel: BRIDGE_PROTOCOL,
    }, port);
    window.setTimeout(() => {
        portEmit?.({
            protocol: BRIDGE_PROTOCOL,
            type: 'GRANT',
            seq: nextSeq(),
            grant_id: grantId,
            identity,
            expires_at_ms: Date.now() + 600000,
            ops: ['snapshot.read', 'report-policy.read', 'enable.read', 'video.open', 'video.close', 'live.subscribe'],
        });
    }, 0);
    const controller = createRuntimeController(session, { pollIntervalMs: 1200 });
    (window as Window & { __lineCrossingRuntimeTest?: unknown }).__lineCrossingRuntimeTest = {
        requests: () => received,
        state: () => controller.getState(),
        refresh: () => controller.refresh(),
        emitLive,
    };
    render(
        <I18nProvider i18n={i18n}>
            <LineCountingModule capabilities={controller.capabilities} />
            <Toaster richColors position="top-right" />
        </I18nProvider>,
        document.getElementById('app')!,
    );
} else {
    const { capabilities, testApi } = createTestCapabilities(
        new URL(window.location.href),
        { startVideoUnavailable: params.get('video') === 'unavailable' },
    );
    (window as Window & { __lineCrossingTest?: typeof testApi }).__lineCrossingTest = testApi;

    render(
        <I18nProvider i18n={i18n}>
            <LineCountingModule capabilities={capabilities} />
            <Toaster richColors position="top-right" />
        </I18nProvider>,
        document.getElementById('app')!,
    );
}
