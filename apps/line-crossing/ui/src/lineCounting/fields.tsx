import { useEffect, useState } from 'preact/hooks';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';

export function Group({ title, children }: { title: string; children: React.ReactNode }) {
    return (
        <div className="border rounded-md p-3 space-y-3">
            <h4 className="text-sm font-semibold text-gray-800">{title}</h4>
            {children}
        </div>
    );
}

function clampNum(v: number, min: number, max: number, step: number) {
    const rounded = step >= 1 ? Math.round(v) : v;
    return Math.max(min, Math.min(max, rounded));
}

export function NumField({
    label, value, min, max, step, onChange, disabled = false, testId,
}: {
    label: string; value: number; min: number; max: number; step: number;
    onChange: (v: number) => void;
    disabled?: boolean;
    testId?: string;
}) {
    const [text, setText] = useState(String(value));
    const [focused, setFocused] = useState(false);

    useEffect(() => {
        if (!focused) setText(String(value));
    }, [value, focused]);

    return (
        <div className="space-y-1" data-testid={testId}>
            <Label className="text-xs">{label}</Label>
            <Input
              type="number"
              value={text}
              min={min}
              max={max}
              step={step}
              disabled={disabled}
              onFocus={() => setFocused(true)}
              onBlur={() => {
                    setFocused(false);
                    const v = Number(text);
                    if (text.trim() === '' || Number.isNaN(v)) {
                        setText(String(value));
                    } else {
                        const c = clampNum(v, min, max, step);
                        onChange(c);
                        setText(String(c));
                    }
                }}
              onChange={(e) => {
                    const raw = (e.target as HTMLInputElement).value;
                    setText(raw);
                    if (raw.trim() === '') return;
                    const v = Number(raw);
                    if (!Number.isNaN(v)) onChange(clampNum(v, min, max, step));
                }}
            />
        </div>
    );
}

export function ToggleField({ label, checked, onChange, disabled = false, testId }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; testId?: string }) {
    return (
        <div className="flex items-center justify-between" data-testid={testId}>
            <Label className="text-xs">{label}</Label>
            <Switch checked={checked} onCheckedChange={onChange} disabled={disabled} />
        </div>
    );
}
