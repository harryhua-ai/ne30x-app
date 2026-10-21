import { useLingui } from '@lingui/react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { LineCountingConfig, LineCountingStatus } from '@/services/api/line-counting';
import { Group, NumField } from './fields';

export interface ConfigPageProps {
    config: LineCountingConfig;
    status: LineCountingStatus;
    writeAllowed: boolean;
    onChange: (patch: Partial<LineCountingConfig>) => void;
}

export default function ConfigPage({
    config,
    status,
    writeAllowed,
    onChange,
}: ConfigPageProps) {
    const { i18n } = useLingui();
    const classes = status.model.classes ?? [];
    const modelLoaded = status.model.name.length > 0;

    return (
        <div className="space-y-3" data-testid="lc-page-config">
            <Group title={i18n._('sys.line_counting.base_group')}>
                <div className="space-y-1">
                    <Label className="text-xs">{i18n._('sys.line_counting.counter_name')}</Label>
                    <Input
                        value={config.counter_name}
                        data-testid="lc-counter-name"
                        disabled={!writeAllowed}
                        onChange={(e) => onChange({ counter_name: (e.target as HTMLInputElement).value })}
                    />
                </div>
                <div className="space-y-1">
                    <Label className="text-xs">{i18n._('sys.line_counting.target_class')}</Label>
                    <Select
                        value={config.target_class}
                        onValueChange={(value) => onChange({ target_class: value })}
                        disabled={!writeAllowed}
                    >
                        <SelectTrigger className="w-full">
                            <SelectValue placeholder={config.target_class} />
                        </SelectTrigger>
                        <SelectContent>
                            {classes.length === 0 && <SelectItem value={config.target_class}>{config.target_class}</SelectItem>}
                            {classes.map((item) => <SelectItem key={item.id} value={item.name}>{item.name}</SelectItem>)}
                        </SelectContent>
                    </Select>
                    <p className="text-[11px] text-gray-400" data-testid="lc-current-model">
                        {modelLoaded
                            ? i18n._('sys.line_counting.current_model').replace('{name}', status.model.name)
                            : i18n._('sys.line_counting.current_model_unknown')}
                    </p>
                </div>
            </Group>

            <Group title={i18n._('sys.line_counting.tracking_group')}>
                <NumField
                    label={i18n._('sys.line_counting.conf_threshold')}
                    value={config.confidence_threshold}
                    min={0}
                    max={1}
                    step={0.05}
                    disabled={!writeAllowed}
                    onChange={(value) => onChange({ confidence_threshold: value })}
                />
                <NumField
                    label={i18n._('sys.line_counting.assoc_distance')}
                    value={config.tracking.association_distance}
                    min={0.05}
                    max={1}
                    step={0.05}
                    disabled={!writeAllowed}
                    onChange={(value) => onChange({ tracking: { ...config.tracking, association_distance: value } })}
                />
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                    <NumField
                        label={i18n._('sys.line_counting.track_history')}
                        value={config.tracking.history_length}
                        min={4}
                        max={16}
                        step={1}
                        disabled={!writeAllowed}
                        onChange={(value) => onChange({ tracking: { ...config.tracking, history_length: value } })}
                    />
                    <NumField
                        label={i18n._('sys.line_counting.max_missed')}
                        value={config.tracking.max_missed_frames}
                        min={1}
                        max={60}
                        step={1}
                        disabled={!writeAllowed}
                        onChange={(value) => onChange({ tracking: { ...config.tracking, max_missed_frames: value } })}
                    />
                    <NumField
                        label={i18n._('sys.line_counting.confirm_frames')}
                        value={config.tracking.confirmation_frames}
                        min={1}
                        max={16}
                        step={1}
                        disabled={!writeAllowed}
                        onChange={(value) => onChange({ tracking: { ...config.tracking, confirmation_frames: value } })}
                    />
                </div>
            </Group>
            {!writeAllowed && <p className="text-xs text-gray-500" data-testid="lc-config-readonly">{i18n._('lineCrossing.readOnly')}</p>}
        </div>
    );
}
