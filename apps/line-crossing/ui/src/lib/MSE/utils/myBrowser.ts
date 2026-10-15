

class BrowserDetector {
    private userAgent: string

    constructor() {
        this.userAgent = navigator.userAgent.toLowerCase()
    }


    isBrowserChrome() {
        return this.userAgent.includes('chrome') && !this.userAgent.includes('edg')
    }


    isBrowserSafari() {
        return this.userAgent.includes('safari') && !this.userAgent.includes('chrome')
    }


    isBrowserFirefox() {
        return this.userAgent.includes('firefox')
    }


    isBrowserEdge() {
        return this.userAgent.includes('edg')
    }


    isBrowserIE() {
        return this.userAgent.includes('msie') || this.userAgent.includes('trident')
    }


    getBrowserName() {
        if (this.isBrowserChrome()) return 'Chrome'
        if (this.isBrowserSafari()) return 'Safari'
        if (this.isBrowserFirefox()) return 'Firefox'
        if (this.isBrowserEdge()) return 'Edge'
        if (this.isBrowserIE()) return 'IE'
        return 'Unknown'
    }


    getBrowserVersion() {
        const match = this.userAgent.match(/(chrome|safari|firefox|edg|msie|trident(?=\/))\/?\s*(\d+)/i)
        return match ? match[2] : 'Unknown'
    }


    static isWebGLSupported(): boolean {
        try {
            const canvas = document.createElement('canvas')

            return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))
        } catch (e) {
            console.error(e)
            return false
        }
    }


    static isMSESupported(): boolean {

        return 'MediaSource' in window
    }


    static isH264Supported(): boolean {
        const video = document.createElement('video')
        return video.canPlayType('video/mp4; codecs="avc1.42E01E"') !== ''
    }


    static isAACSupported(): boolean {
        const video = document.createElement('video')
        return video.canPlayType('audio/mp4; codecs="mp4a.40.2"') !== ''
    }
}

export default new BrowserDetector()
