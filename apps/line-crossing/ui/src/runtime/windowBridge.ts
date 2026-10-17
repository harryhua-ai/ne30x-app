import { BRIDGE_CHANNEL, validateHello } from './bridgeProtocol';
import { BridgeSession, type PortLike } from './bridgeSession';

export function connectHostBridge(): BridgeSession {
    const session = new BridgeSession();
    if (typeof window === 'undefined' || window.parent === window) return session;
    if (self.origin === 'null' || self.origin === '') return session;
    let settled = false;
    const onMessage = (event: MessageEvent) => {
        if (settled) return;
        if (!event.isTrusted) return;
        if (event.source !== window.parent) return;
        if (typeof event.origin !== 'string' || event.origin === '' || event.origin === 'null') return;
        const ports: readonly MessagePort[] = event.ports;
        if (!ports || ports.length !== 1) return;
        if (!validateHello(event.data).ok) return;
        const hello = event.data as { channel?: unknown };
        if (hello.channel !== BRIDGE_CHANNEL) return;
        const port: PortLike = {
            postMessage: (data) => ports[0].postMessage(data),
            close: () => ports[0].close(),
            start: () => ports[0].start(),
            addEventListener: (type, listener) => ports[0].addEventListener(type, listener as EventListener),
            removeEventListener: (type, listener) => ports[0].removeEventListener(type, listener as EventListener),
        };
        if (session.acceptHello(event.data, port)) settled = true;
    };
    window.addEventListener('message', onMessage);
    return session;
}
