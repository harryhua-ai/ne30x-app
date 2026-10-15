import { i18n } from '@lingui/core';
import enSource from './locales/en/messages.json';
import zhSource from './locales/zh/messages.json';

const appMessages = {
    en: {
        'lineCrossing.unavailable': 'Unavailable',
        'lineCrossing.unknown': 'Unknown',
        'lineCrossing.stale': 'Stale',
        'lineCrossing.live': 'Live',
        'lineCrossing.reconnecting': 'Reconnecting',
        'lineCrossing.saveApp': 'Save App settings',
        'lineCrossing.saveHost': 'Save Host settings',
        'lineCrossing.appOwned': 'App-owned settings',
        'lineCrossing.hostOwned': 'Host-owned settings',
        'lineCrossing.statsUnavailable': 'Statistics unavailable',
        'lineCrossing.eventsUnavailable': 'Events unavailable',
        'lineCrossing.readOnly': 'Read-only',
        'lineCrossing.applied': 'Applied',
        'lineCrossing.conflict': 'Conflict; reload the current snapshot',
        'lineCrossing.unknownOutcome': 'Outcome unknown; no automatic retry was sent',
        'lineCrossing.saveUnavailable': 'Save capability unavailable',
        'lineCrossing.resetUnavailable': 'Reset capability unavailable',
        'lineCrossing.retryVideo': 'Retry video',
        'lineCrossing.discard': 'Discard changes',
        'lineCrossing.resetLineTitle': 'Reset counting line?',
        'lineCrossing.resetLineBody': 'This replaces the current line draft with the default center line.',
        'lineCrossing.confirmResetLine': 'Reset line',
        'lineCrossing.videoExpired': 'Video authorization expired',
        'lineCrossing.sessionChanged': 'App session changed; reload the current snapshot',
    },
    zh: {
        'lineCrossing.unavailable': '不可用',
        'lineCrossing.unknown': '未知',
        'lineCrossing.stale': '数据已过期',
        'lineCrossing.live': '实时播放',
        'lineCrossing.reconnecting': '重新连接中',
        'lineCrossing.saveApp': '保存 App 设置',
        'lineCrossing.saveHost': '保存 Host 设置',
        'lineCrossing.appOwned': 'App 管理的设置',
        'lineCrossing.hostOwned': 'Host 管理的设置',
        'lineCrossing.statsUnavailable': '统计数据不可用',
        'lineCrossing.eventsUnavailable': '事件数据不可用',
        'lineCrossing.readOnly': '只读',
        'lineCrossing.applied': '已应用',
        'lineCrossing.conflict': '配置冲突，请重新加载当前快照',
        'lineCrossing.unknownOutcome': '结果未知；未自动重试',
        'lineCrossing.saveUnavailable': '保存能力不可用',
        'lineCrossing.resetUnavailable': '重置能力不可用',
        'lineCrossing.retryVideo': '重试视频',
        'lineCrossing.discard': '撤销修改',
        'lineCrossing.resetLineTitle': '重置计数线？',
        'lineCrossing.resetLineBody': '将当前线条草稿替换为默认中心线。',
        'lineCrossing.confirmResetLine': '重置计数线',
        'lineCrossing.videoExpired': '视频授权已过期',
        'lineCrossing.sessionChanged': 'App 会话已变化，请重新加载当前快照',
    },
};

i18n.load('en', { ...enSource, ...appMessages.en });
i18n.load('zh', { ...zhSource, ...appMessages.zh });
i18n.activate(navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en');

export { i18n };
