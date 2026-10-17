import { useCallback, useEffect, useRef, useState } from 'preact/hooks';
import { useLingui } from '@lingui/react';
import H264Player from '@/lib/MSE/h264Player';
import { Button } from '@/components/ui/button';
import { RefreshCw } from 'lucide-react';
import type { Capability, LineCountingConfig, LineCountingState, VideoStreamGrant } from '@/services/api/line-counting';

export interface LineTrackDot {
    track_id: number;
    points: Array<{ x: number; y: number }>;
}

export interface VideoPreviewProps {
    config: LineCountingConfig | null;
    draft: LineCountingConfig | null;
    editMode: boolean;
    editPhase: 0 | 1 | 2;
    writeAllowed: boolean;
    state?: LineCountingState;
    tracks?: LineTrackDot[];
    video: Capability<VideoStreamGrant>;
    onRequestVideo: () => void;
    onPickPoint: (permilleX: number, permilleY: number) => void;
    onDragEndpoint: (endpoint: 'start' | 'end', permilleX: number, permilleY: number) => void;
}

type ConnectionState = 'live' | 'reconnecting' | 'unavailable';

const STATE_BADGE_KEY: Record<string, string> = {
    running: 'sys.line_counting.state_running',
    stopped: 'sys.line_counting.state_disabled',
    unknown: 'lineCrossing.unknown',
};

export default function VideoPreview({
    config,
    draft,
    editMode,
    editPhase,
    writeAllowed,
    state,
    tracks = [],
    video,
    onRequestVideo,
    onPickPoint,
    onDragEndpoint,
}: VideoPreviewProps) {
    const { i18n } = useLingui();
    const playerRef = useRef<H264Player | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const stageRef = useRef<HTMLDivElement>(null);
    const dragTargetRef = useRef<'start' | 'end' | null>(null);
    const dragCallbackRef = useRef(onDragEndpoint);
    const lastDragAtRef = useRef(0);
    const [reloading, setReloading] = useState(false);
    const [size, setSize] = useState({ w: 0, h: 0 });
    const [aspect, setAspect] = useState(16 / 9);
    const [connectionState, setConnectionState] = useState<ConnectionState>('unavailable');

    dragCallbackRef.current = onDragEndpoint;

    useEffect(() => {
        const handleMove = (event: PointerEvent) => {
            const endpoint = dragTargetRef.current;
            const stage = stageRef.current;
            if (!endpoint || !stage) return;
            const rect = stage.getBoundingClientRect();
            if (!rect.width || !rect.height) return;
            const x = Math.max(0, Math.min(1000, Math.round(((event.clientX - rect.left) / rect.width) * 1000)));
            const y = Math.max(0, Math.min(1000, Math.round(((event.clientY - rect.top) / rect.height) * 1000)));
            dragCallbackRef.current(endpoint, x, y);
            lastDragAtRef.current = Date.now();
        };
        const clearDrag = () => { dragTargetRef.current = null; };
        window.addEventListener('pointermove', handleMove);
        window.addEventListener('pointerup', clearDrag);
        window.addEventListener('pointercancel', clearDrag);
        return () => {
            window.removeEventListener('pointermove', handleMove);
            window.removeEventListener('pointerup', clearDrag);
            window.removeEventListener('pointercancel', clearDrag);
        };
    }, []);

    useEffect(() => {
        if (video.state !== 'available') {
            setConnectionState('unavailable');
            return undefined;
        }
        const grant = video.value;
        if (grant.sessionGeneration < 1 || grant.expiresAtMs <= Date.now() || !videoRef.current) {
            setConnectionState('unavailable');
            return undefined;
        }
        setConnectionState('reconnecting');
        let expired = false;
        const expiryTimer = window.setTimeout(() => {
            expired = true;
            setConnectionState('unavailable');
            playerRef.current?.destroy();
            playerRef.current = null;
            grant.release();
        }, Math.max(0, grant.expiresAtMs - Date.now()));
        const onWork = (event: Event) => {
            const connected = (event as CustomEvent<boolean>).detail;
            if (!connected) {
                setConnectionState('reconnecting');
                return;
            }
            const element = videoRef.current;
            if (element && !element.paused && element.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) setConnectionState('live');
        };
        const onClose = () => setConnectionState('reconnecting');
        const onError = () => setConnectionState('reconnecting');
        window.addEventListener('wv_work', onWork);
        window.addEventListener('wv_close', onClose);
        window.addEventListener('wv_error', onError);
        const player = new H264Player((message) => {
            if (expired) return;
            if (message.t === 'startPlay') setConnectionState('live');
            if (message.t === 'mseError') setConnectionState('reconnecting');
            if (message.t === 'connectionUnavailable') {
                setConnectionState('unavailable');
                playerRef.current?.destroy();
                playerRef.current = null;
            }
        });
        playerRef.current = player;
        player.initPlayer(videoRef.current);
        player.start(grant.url).catch(() => setConnectionState('unavailable'));
        return () => {
            window.clearTimeout(expiryTimer);
            window.removeEventListener('wv_work', onWork);
            window.removeEventListener('wv_close', onClose);
            window.removeEventListener('wv_error', onError);
            player.destroy();
            if (playerRef.current === player) playerRef.current = null;
            grant.release();
        };
    }, [video]);

    useEffect(() => {
        const element = stageRef.current;
        if (!element) return undefined;
        const update = () => setSize({ w: element.clientWidth, h: element.clientHeight });
        update();
        const observer = new ResizeObserver(update);
        observer.observe(element);
        return () => observer.disconnect();
    }, []);

    const toPoint = useCallback((clientX: number, clientY: number) => {
        const element = stageRef.current;
        if (!element) return null;
        const rect = element.getBoundingClientRect();
        if (!rect.width || !rect.height) return null;
        return {
            x: Math.max(0, Math.min(1000, Math.round(((clientX - rect.left) / rect.width) * 1000))),
            y: Math.max(0, Math.min(1000, Math.round(((clientY - rect.top) / rect.height) * 1000))),
        };
    }, []);

    const handleStageClick = useCallback((event: MouseEvent) => {
        if (!editMode || !writeAllowed || Date.now() - lastDragAtRef.current < 250) return;
        const point = toPoint(event.clientX, event.clientY);
        if (point) onPickPoint(point.x, point.y);
    }, [editMode, onPickPoint, toPoint, writeAllowed]);

    const startDrag = (endpoint: 'start' | 'end', event: PointerEvent) => {
        if (!editMode || !writeAllowed || event.button !== 0) return;
        event.preventDefault();
        event.stopPropagation();
        dragTargetRef.current = endpoint;
        (event.currentTarget as SVGCircleElement).setPointerCapture?.(event.pointerId);
        const point = toPoint(event.clientX, event.clientY);
        if (point) dragCallbackRef.current(endpoint, point.x, point.y);
        lastDragAtRef.current = Date.now();
    };

    const { w, h } = size;
    const p2px = (permille: number, dim: number) => (permille / 1000) * dim;
    const lineDirty = !!config && !!draft && JSON.stringify(draft.line) !== JSON.stringify(config.line);
    const effective = draft ?? config;
    const hasLine = !!effective && (effective.line.x1 !== effective.line.x2 || effective.line.y1 !== effective.line.y2);
    const showOverlay = (state === 'running' || editMode) && w > 0 && h > 0;
    const x1 = effective ? p2px(effective.line.x1, w) : 0;
    const y1 = effective ? p2px(effective.line.y1, h) : 0;
    const x2 = effective ? p2px(effective.line.x2, w) : 0;
    const y2 = effective ? p2px(effective.line.y2, h) : 0;
    const ox = effective ? p2px(effective.line.outside_x, w) : 0;
    const oy = effective ? p2px(effective.line.outside_y, h) : 0;
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    let dx = mx - ox;
    let dy = my - oy;
    const dlen = Math.hypot(dx, dy) || 1;
    dx /= dlen;
    dy /= dlen;
    const arrowLength = Math.max(30, Math.min(w, h) * 0.07);
    const tipX = mx + dx * arrowLength;
    const tipY = my + dy * arrowLength;
    const baseX = mx + dx * arrowLength * 0.3;
    const baseY = my + dy * arrowLength * 0.3;
    const angle = Math.atan2(dy, dx);
    const head = 13;
    const h1x = tipX - head * Math.cos(angle - Math.PI / 6);
    const h1y = tipY - head * Math.sin(angle - Math.PI / 6);
    const h2x = tipX - head * Math.cos(angle + Math.PI / 6);
    const h2y = tipY - head * Math.sin(angle + Math.PI / 6);
    const badgeText = state ? i18n._(STATE_BADGE_KEY[state]) : i18n._('lineCrossing.unknown');
    const hint = !editMode ? null
        : editPhase === 0 ? i18n._('sys.line_counting.hint_start')
        : editPhase === 1 ? i18n._('sys.line_counting.hint_end')
        : i18n._('sys.line_counting.hint_draft');
    const connectionLabel = i18n._(`lineCrossing.${connectionState}`);

    return (
        <div className="relative flex h-full min-h-0 w-full items-center justify-center bg-black">
            <div
                ref={stageRef}
                className={`relative w-full ${editMode && writeAllowed ? 'cursor-crosshair' : ''}`}
                onClick={handleStageClick}
                data-testid="lc-stage"
            >
                <video
                    ref={videoRef}
                    className="block h-auto w-full"
                    id="lcVideoPlayer"
                    style={{ aspectRatio: String(aspect) }}
                    muted
                    playsInline
                    disableRemotePlayback
                    onLoadedMetadata={(event) => {
                        const element = event.currentTarget;
                        if (element.videoWidth && element.videoHeight) setAspect(element.videoWidth / element.videoHeight);
                    }}
                />
                {showOverlay && (
                    <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox={`0 0 ${w} ${h}`} data-testid="lc-overlay">
                        {tracks.map((track) => (
                            <g key={track.track_id} data-testid="lc-track">
                                {track.points.length > 1 && <polyline points={track.points.map((point) => `${p2px(point.x, w)},${p2px(point.y, h)}`).join(' ')} fill="none" stroke="rgba(56,189,248,0.75)" strokeWidth={2} />}
                                {track.points.length > 0 && <circle cx={p2px(track.points[track.points.length - 1].x, w)} cy={p2px(track.points[track.points.length - 1].y, h)} r={5} fill="rgba(56,189,248,0.9)" />}
                            </g>
                        ))}
                        {hasLine && <g data-testid="lc-line">
                            <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#f59e0b" strokeWidth={18} strokeOpacity={0.14} strokeLinecap="round" />
                            <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#fbbf24" strokeWidth={9} strokeOpacity={0.3} strokeLinecap="round" />
                            <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#fde047" strokeWidth={3.5} strokeLinecap="round" strokeDasharray={editMode || lineDirty ? '14 10' : undefined} />
                        </g>}
                        {hasLine && <>
                            <line x1={baseX} y1={baseY} x2={tipX} y2={tipY} stroke="#f97316" strokeWidth={4.5} strokeLinecap="round" />
                            <polygon points={`${tipX},${tipY} ${h1x},${h1y} ${h2x},${h2y}`} fill="#f97316" />
                        </>}
                        {editMode && editPhase >= 1 && <>
                            <circle cx={x1} cy={y1} r={13} fill="none" stroke="#fde047" strokeWidth={2.5} strokeOpacity={0.5} />
                            <circle cx={x1} cy={y1} r={5} fill="#fde047" />
                        </>}
                        {editMode && hasLine && <>
                            <circle
                                cx={x1}
                                cy={y1}
                                r={10}
                                fill="#fde047"
                                stroke="#fff"
                                strokeWidth={2}
                                className={writeAllowed ? 'pointer-events-auto cursor-grab' : 'pointer-events-none'}
                                style={{ touchAction: 'none' }}
                                role="slider"
                                aria-label="Line start"
                                data-testid="lc-line-endpoint"
                                data-endpoint="start"
                                onPointerDown={(event) => startDrag('start', event)}
                            />
                            <circle
                                cx={x2}
                                cy={y2}
                                r={10}
                                fill="#fde047"
                                stroke="#fff"
                                strokeWidth={2}
                                className={writeAllowed ? 'pointer-events-auto cursor-grab' : 'pointer-events-none'}
                                style={{ touchAction: 'none' }}
                                role="slider"
                                aria-label="Line end"
                                data-testid="lc-line-endpoint"
                                data-endpoint="end"
                                onPointerDown={(event) => startDrag('end', event)}
                            />
                            <circle cx={ox} cy={oy} r={9} fill="rgba(59,130,246,0.65)" stroke="#fff" strokeWidth={2} />
                        </>}
                    </svg>
                )}
                <div className={`absolute left-2 top-2 z-10 rounded px-2.5 py-1 text-xs text-white backdrop-blur-sm ${state === 'running' ? 'bg-emerald-600/80' : state === 'stopped' ? 'bg-gray-600/80' : 'bg-gray-700/80'}`} data-testid="lc-runtime-badge">
                    {badgeText}
                </div>
                <div
                    className={`absolute left-1/2 top-2 z-10 -translate-x-1/2 rounded px-3 py-1 text-[11px] backdrop-blur-sm ${connectionState === 'live' ? 'bg-emerald-700/80 text-white' : connectionState === 'reconnecting' ? 'bg-black/70 text-amber-300' : 'bg-gray-700/90 text-gray-100'}`}
                    data-testid="lc-video-state"
                    data-state={connectionState}
                >
                    {connectionLabel}
                </div>
                {connectionState !== 'live' && <Button
                    variant="outline"
                    size="sm"
                    className="absolute right-2 top-2 z-10 h-7 border-white/20 bg-black/50 px-2 text-xs text-white hover:bg-black/70"
                    onClick={() => {
                        setReloading(true);
                        onRequestVideo();
                        window.setTimeout(() => setReloading(false), 800);
                    }}
                    disabled={reloading}
                    data-testid="lc-video-retry"
                >
                    <RefreshCw className={`mr-1 h-3 w-3 ${reloading ? 'animate-spin' : ''}`} />
                    {i18n._('lineCrossing.retryVideo')}
                </Button>}
                {hint && <div className="pointer-events-none absolute bottom-2 left-2 z-10 rounded bg-black/60 px-2 py-1 text-xs text-amber-200" data-testid="lc-video-hint">{hint}</div>}
            </div>
        </div>
    );
}
