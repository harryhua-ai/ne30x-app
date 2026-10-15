import { render } from 'preact';
import { I18nProvider } from '@lingui/react';
import { Toaster } from 'sonner';
import LineCountingModule from '../../../apps/line-crossing/ui/src/LineCountingModule';
import { i18n } from '../../../apps/line-crossing/ui/src/i18n';
import { createTestCapabilities } from './test-capabilities';
import '../../../apps/line-crossing/ui/src/styles/index.css';

const { capabilities, testApi } = createTestCapabilities(new URL(window.location.href));
(window as Window & { __lineCrossingTest?: typeof testApi }).__lineCrossingTest = testApi;

render(
    <I18nProvider i18n={i18n}>
        <LineCountingModule capabilities={capabilities} />
        <Toaster richColors position="top-right" />
    </I18nProvider>,
    document.getElementById('app')!,
);
