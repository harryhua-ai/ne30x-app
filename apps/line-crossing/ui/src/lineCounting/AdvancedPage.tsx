import { useLingui } from '@lingui/react';
import type { Capability, HostPolicyConfig, HostPolicySnapshot, LineCountingConfig } from '@/services/api/line-counting';
import { Button } from '@/components/ui/button';
import { Group, NumField, ToggleField } from './fields';

export interface AdvancedPageProps {
    config: LineCountingConfig | null;
    hostPolicy: Capability<HostPolicySnapshot>;
    appWriteAllowed: boolean;
    hostWriteAllowed: boolean;
    appSaving: boolean;
    hostSaving: boolean;
    appFeedback: string | null;
    hostFeedback: string | null;
    onAppChange: (patch: Partial<LineCountingConfig>) => void;
    onHostChange: (patch: Partial<HostPolicyConfig>) => void;
    onSaveApp: () => void;
    onSaveHost: () => void;
}

export default function AdvancedPage({
    config,
    hostPolicy,
    appWriteAllowed,
    hostWriteAllowed,
    appSaving,
    hostSaving,
    appFeedback,
    hostFeedback,
    onAppChange,
    onHostChange,
    onSaveApp,
    onSaveHost,
}: AdvancedPageProps) {
    const { i18n } = useLingui();
    const hostConfig = hostPolicy.state === 'available' ? hostPolicy.value.config : null;

    return (
        <div className="space-y-3" data-testid="lc-page-advanced">
            <Group title={i18n._('lineCrossing.appOwned')}>
                {config
                    ? <>
                        <NumField
                            label={i18n._('sys.line_counting.window_minutes')}
                            testId="lc-app-window-minutes"
                            value={config.window_minutes}
                            min={1}
                            max={1440}
                            step={1}
                            disabled={!appWriteAllowed}
                            onChange={(value) => onAppChange({ window_minutes: value })}
                        />
                        <ToggleField
                            label={i18n._('sys.line_counting.tracks_report')}
                            testId="lc-app-tracks-enabled"
                            checked={config.reporting.tracks_enabled}
                            disabled={!appWriteAllowed}
                            onChange={(value) => onAppChange({ reporting: { ...config.reporting, tracks_enabled: value } })}
                        />
                        <ToggleField
                            label={i18n._('sys.line_counting.heat_report')}
                            testId="lc-app-heat-enabled"
                            checked={config.reporting.heat_grid_enabled}
                            disabled={!appWriteAllowed}
                            onChange={(value) => onAppChange({ reporting: { ...config.reporting, heat_grid_enabled: value } })}
                        />
                    </>
                    : <p data-testid="lc-app-settings-unavailable">{i18n._('lineCrossing.unavailable')}</p>}
                <div className="flex items-center justify-end gap-3">
                    {appFeedback && <span role="status" data-testid="lc-app-save-status">{i18n._(appFeedback)}</span>}
                    <Button onClick={onSaveApp} disabled={!config || !appWriteAllowed || appSaving} data-testid="lc-save-app">
                        {appSaving ? i18n._('sys.line_counting.saving') : i18n._('lineCrossing.saveApp')}
                    </Button>
                </div>
            </Group>
            <Group title={i18n._('lineCrossing.hostOwned')}>
                {hostConfig
                    ? <>
                        <ToggleField
                            label={i18n._('sys.line_counting.mqtt_report')}
                            testId="lc-host-mqtt-enabled"
                            checked={hostConfig.mqtt_enabled}
                            disabled={!hostWriteAllowed}
                            onChange={(value) => onHostChange({ mqtt_enabled: value })}
                        />
                        <ToggleField
                            label={i18n._('sys.line_counting.webhook_report')}
                            testId="lc-host-webhook-enabled"
                            checked={hostConfig.webhook_enabled}
                            disabled={!hostWriteAllowed}
                            onChange={(value) => onHostChange({ webhook_enabled: value })}
                        />
                        <NumField
                            label={i18n._('sys.line_counting.backlog_capacity')}
                            testId="lc-host-backlog-capacity"
                            value={hostConfig.backlog_capacity}
                            min={1}
                            max={8}
                            step={1}
                            disabled={!hostWriteAllowed}
                            onChange={(value) => onHostChange({ backlog_capacity: value })}
                        />
                    </>
                    : <p data-testid="lc-host-settings-unavailable" title={hostPolicy.state === 'unavailable' || hostPolicy.state === 'stale' ? hostPolicy.reason : undefined}>{hostPolicy.state === 'stale' ? i18n._('lineCrossing.stale') : i18n._('lineCrossing.unavailable')}</p>}
                <div className="flex items-center justify-end gap-3">
                    {hostFeedback && <span role="status" data-testid="lc-host-save-status">{i18n._(hostFeedback)}</span>}
                    <Button onClick={onSaveHost} disabled={!hostConfig || !hostWriteAllowed || hostSaving} data-testid="lc-save-host">
                        {hostSaving ? i18n._('sys.line_counting.saving') : i18n._('lineCrossing.saveHost')}
                    </Button>
                </div>
            </Group>
        </div>
    );
}
