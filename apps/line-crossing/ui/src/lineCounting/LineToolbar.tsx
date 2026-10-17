import { useLingui } from '@lingui/react';
import { Button } from '@/components/ui/button';

export interface LineToolbarProps {
    editMode: boolean;
    editPhase: 0 | 1 | 2;
    hasLine: boolean;
    disabled?: boolean;
    onToggleEdit: () => void;
    onFinishDraw: () => void;
    onFlipDirection: () => void;
    onResetLine: () => void;
}

export default function LineToolbar({
    editMode, editPhase, hasLine, disabled = false,
    onToggleEdit, onFinishDraw, onFlipDirection, onResetLine,
}: LineToolbarProps) {
    const { i18n } = useLingui();
    const hint = !editMode ? null
        : editPhase === 0 ? i18n._('sys.line_counting.hint_start')
        : editPhase === 1 ? i18n._('sys.line_counting.hint_end')
        : i18n._('sys.line_counting.hint_draft');

    return (
      <div className="flex flex-wrap items-center gap-2" data-testid="lc-line-toolbar">
            <Button size="sm" variant={editMode ? 'default' : 'outline'} onClick={editMode ? onFinishDraw : onToggleEdit} disabled={disabled}>
                {editMode ? i18n._('sys.line_counting.finish_save') : i18n._('sys.line_counting.draw_line')}
            </Button>
            <Button size="sm" variant="outline" onClick={onFlipDirection} disabled={disabled || !hasLine}>
                {i18n._('sys.line_counting.flip_direction')}
            </Button>
            <Button size="sm" variant="outline" onClick={onResetLine} disabled={disabled}>
                {i18n._('sys.line_counting.reset_line')}
            </Button>
            {hint && (
                <span className="text-xs text-amber-600" data-testid="lc-toolbar-hint">{hint}</span>
            )}
      </div>
    );
}
