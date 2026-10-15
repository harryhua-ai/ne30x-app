

interface BufferedFrame {
    data: Uint8Array;
    timestamp: number;
    receivedAt: number;
}

export class JitterBuffer {
    private buffer: BufferedFrame[] = [];

    private readonly frameInterval: number = 40;

    private readonly minBufferSize: number = 10;

    private readonly maxBufferSize: number = 50;

    private readonly lowWaterMark: number = 5;

    private sequence: number = 0;

    private isPlaying: boolean = false;

    initialize(): void {
        this.buffer = [];
        this.sequence = 0;
        this.isPlaying = false;
    }

    addFrame(data: Uint8Array): void {
        if (data.length === 0) return;

        const receivedAt = Date.now();
        const timestamp = this.sequence * this.frameInterval;
        this.buffer.push({ data, timestamp, receivedAt });
        this.sequence++;


        if (this.buffer.length > this.maxBufferSize) {

            const now = Date.now();
            const maxDelay = 1000;


            while (this.buffer.length > this.maxBufferSize * 0.8) {
                const oldestFrame = this.buffer[0];
                const delay = now - oldestFrame.receivedAt;
                if (delay > maxDelay) {
                    this.buffer.shift();
                } else {
                    break;
                }
            }


            while (this.buffer.length > this.maxBufferSize) {
                this.buffer.shift();
            }
        }


        if (!this.isPlaying && this.buffer.length >= this.minBufferSize) {
            this.isPlaying = true;
        }
    }

    getNextFrame(): BufferedFrame | null {
        if (!this.isPlaying || this.buffer.length === 0) {
            return null;
        }

        const frame = this.buffer.shift();


        if (this.buffer.length < this.lowWaterMark) {
            this.isPlaying = false;
        }

        return frame || null;
    }

    getBufferSize(): number {
        return this.buffer.length;
    }

    clear(): void {
        this.buffer = [];
        this.sequence = 0;
        this.isPlaying = false;
    }
}
