
export const DeviceDetector = {

  isAndroid(): boolean {
    if (typeof window === 'undefined') return false;
    return /Android/i.test(navigator.userAgent);
  },


  isMobile(): boolean {
    if (typeof window === 'undefined') return false;
    return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  },


  isTouchDevice(): boolean {
    if (typeof window === 'undefined') return false;
    return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  },


  getDeviceInfo() {
    if (typeof window === 'undefined') {
      return {
        userAgent: 'SSR',
        isAndroid: false,
        isMobile: false,
        isTouch: false,
        platform: 'unknown'
      };
    }

    return {
      userAgent: navigator.userAgent,
      isAndroid: this.isAndroid(),
      isMobile: this.isMobile(),
      isTouch: this.isTouchDevice(),
      platform: navigator.platform
    };
  },


  debug() {
    const info = this.getDeviceInfo();
    return info;
  }
};


export const { isAndroid, isMobile, isTouchDevice } = DeviceDetector;
