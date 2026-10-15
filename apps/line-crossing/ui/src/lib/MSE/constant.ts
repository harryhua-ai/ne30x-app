


export const playerEvent = {
    startPlay: 'startPlay',
    stopPlay: 'stopPlay',
    mseError: 'mseError',
    codecChanged: 'codecChanged',
    videoError: 'videoError',
    audioError: 'audioError'
}


export const playerStateIdle = 0
export const playerStatePlaying = 1
export const playerStatePaused = 2
export const playerStateError = 3


export const decodeourceType = {
    video: 'video',
    audio: 'audio'
}


export const frameHeaderSize = 88


export const specialDuration = 1
export const maxDuration = 10




export const previewFrameMs = 40;
export const maxFrameMs = maxDuration * 1000;


export const playDebug = false
export const displaySelf = false


export const resolution1080p = 1920 * 1080


export const frameType = {
    IFrame: 1,
    PFrame: 0
}


export const codecType = {
    H264: 0x1B,
    H265: 0x48323635
}
