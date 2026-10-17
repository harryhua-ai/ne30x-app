import { render } from 'preact';
import { I18nProvider } from '@lingui/react';
import { Toaster } from 'sonner';
import LineCountingModule from './LineCountingModule';
import { i18n } from './i18n';
import './styles/index.css';

render(
    <I18nProvider i18n={i18n}>
        <LineCountingModule />
        <Toaster richColors position="top-right" />
    </I18nProvider>,
    document.getElementById('app')!,
);
