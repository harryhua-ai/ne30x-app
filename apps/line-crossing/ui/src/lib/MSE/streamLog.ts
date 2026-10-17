export function logStreamError(channel: string, event: string, code: string, message: string): void {
    window.dispatchEvent(new CustomEvent('line-crossing-media-diagnostic', {
        detail: { channel, event, code, message },
    }));
}
