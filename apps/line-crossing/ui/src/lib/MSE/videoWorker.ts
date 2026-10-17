
interface JMuxerConfig {
    node?: string | HTMLVideoElement;
    mode?: 'video' | 'audio' | 'both';
    flushingTime?: number;
    clearBuffer?: boolean;
    fps?: number;
    debug?: boolean;
    onReady?: () => void;
    onError?: (error: any) => void;
}

interface JMuxerFeedData {
    video?: ArrayBuffer | Uint8Array;
    audio?: ArrayBuffer;
    time?: number;
    iChannelId?: number;
    userData?: any;
}

interface JMuxer {
    feed(data: JMuxerFeedData): void;
    destroy(): void;
}


interface VideoWorkerMessage {
    cmd: 'stop' | 'reset' | 'video';
    data?: ArrayBuffer | Uint8Array;
    videoTime?: number;
    iChannelId?: number;
    userData?: any;
}


declare const JMuxer: {
    new(config?: JMuxerConfig): JMuxer;
};

importScripts(new URL('./jmuxer.min.js', self.location.href).toString());

const createMuxer = (): JMuxer => new JMuxer({ fps: 25 });
let jmuxer: JMuxer = createMuxer();
let animationFrameId: number | null = null;
let jmuxerCmd: MessageEvent<VideoWorkerMessage>[] = [];

function receiveMessage(event: MessageEvent<VideoWorkerMessage>): void {
    if (animationFrameId === null) {
        animationFrameId = requestAnimationFrame(dealJmuxerCmd);
    }
    jmuxerCmd.push(event);
}

function dealJmuxerCmd(): void {
    while (jmuxerCmd.length > 0) {
        const event = jmuxerCmd.shift();
        if (event === undefined) {
            break;
        }
        const msg = event.data;

        switch (msg.cmd) {
            case 'stop':
                jmuxer.destroy();
                if (animationFrameId !== null) {
                    cancelAnimationFrame(animationFrameId);
                    animationFrameId = null;
                }
                jmuxerCmd = [];

                self.close();
                return;
            case 'reset':




                try { jmuxer.destroy(); } catch {  }
                jmuxer = createMuxer();
                jmuxerCmd = [];
                break;
            case 'video':
                if (msg.data) {
                    const videoBytes: Uint8Array = msg.data instanceof Uint8Array
                        ? msg.data
                        : new Uint8Array(msg.data);
                    if (videoBytes.byteLength === 0) break;

                    jmuxer.feed({
                        video: videoBytes,
                        time: msg.videoTime,
                        iChannelId: msg.iChannelId,
                        userData: msg.userData,
                    });
                }
                break;
            default:
                break;
        }
    }

    animationFrameId = null;
}

onmessage = receiveMessage;
