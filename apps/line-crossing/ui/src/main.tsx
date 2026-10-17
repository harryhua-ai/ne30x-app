import { render } from 'preact';
import { I18nProvider } from '@lingui/react';
import { Toaster } from 'sonner';
import LineCountingModule from './LineCountingModule';
import { i18n } from './i18n';
import { createRuntimeCapabilities } from './runtime/runtimeCapabilities';
import { connectHostBridge } from './runtime/windowBridge';
import { unavailableCapabilities } from './services/api/line-counting';
import './styles/index.css';

const framed = typeof window !== 'undefined' && window.parent !== window;
const capabilities = framed ? createRuntimeCapabilities(connectHostBridge()) : unavailableCapabilities;

render(
    <I18nProvider i18n={i18n}>
        <LineCountingModule capabilities={capabilities} />
        <Toaster richColors position="top-right" />
    </I18nProvider>,
    document.getElementById('app')!,
);
