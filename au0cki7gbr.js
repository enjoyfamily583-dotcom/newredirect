/**
 * Advanced Bot Detection System
 * Multi-layered approach combining CDP, fingerprinting, and behavioral analysis
 */

class AdvancedBotDetector {
    constructor(config = {}) {
        this.config = {
            cdpWeight: 50,
            behaviorWeight: 40,
            fingerprintWeight: 30,
            timingWeight: 25,
            navigatorWeight: 20,
            threshold: 70,
            behaviorTimeout: 3000,
            ...config
        };

        this.score = 0;
        this.checks = {};
        this.behaviors = {
            mouseMove: false,
            click: false,
            scroll: false,
            keyboard: false,
            touch: false
        };

        this.startTime = Date.now();
        this.fingerprint = null;
    }

    /**
     * Run all detection checks
     */
    async detect() {
        // Immediate checks
        this.detectCDP();
        this.detectWebDriver();
        this.detectHeadless();
        this.checkNavigatorInconsistencies();
        this.checkAutomationArtifacts();

        // Fingerprinting
        await this.generateFingerprint();

        // REMOVED: Behavior tracking - not used for scoring

        // Calculate final score
        this.calculateScore();

        return {
            isBot: this.score >= this.config.threshold,
            score: this.score,
            checks: this.checks,
            behaviors: this.behaviors,
            fingerprint: this.fingerprint
        };
    }

    /**
     * Detect Chrome DevTools Protocol (most effective single check)
     */
    detectCDP() {
        let detected = false;

        // Method 1: Error stack serialization
        const err = new Error();
        Object.defineProperty(err, 'stack', {
            configurable: true,
            get() {
                detected = true;
                return '';
            }
        });

        // Trigger stack access (CDP serializes on console.debug)
        console.debug(err);

        this.checks.cdp = detected;

        // REMOVED: Console timing check was too sensitive and caused false positives
        // on slower devices/mobile. The error stack serialization method above is sufficient.

        if (detected) {
            this.score += this.config.cdpWeight;
        }

        return detected;
    }

    /**
     * Detect WebDriver flag
     */
    detectWebDriver() {
        this.checks.webdriver = navigator.webdriver === true;

        if (this.checks.webdriver) {
            this.score += 45;
        }

        return this.checks.webdriver;
    }

    /**
     * Detect headless browsers
     */
    detectHeadless() {
        const signals = [];

        // HeadlessChrome user agent
        if (/HeadlessChrome/i.test(navigator.userAgent)) {
            signals.push('headless-ua');
        }

        // Chrome without chrome object
        if (!window.chrome && /Chrome/i.test(navigator.userAgent)) {
            signals.push('missing-chrome-object');
        }

        // Missing plugins (common in headless)
        if (navigator.plugins.length === 0) {
            signals.push('no-plugins');
        }

        // Missing mime types
        if (navigator.mimeTypes.length === 0) {
            signals.push('no-mimetypes');
        }

        // Empty languages array
        if (!navigator.languages || navigator.languages.length === 0) {
            signals.push('no-languages');
        }

        // PhantomJS
        if (window.callPhantom || window._phantom) {
            signals.push('phantomjs');
        }

        // Permissions API inconsistency (headless can't handle permissions)
        if ('permissions' in navigator) {
            this.checkPermissionsAsync();
        }

        this.checks.headlessSignals = signals;

        if (signals.length > 0) {
            this.score += Math.min(signals.length * 15, 45);
        }

        return signals.length > 0;
    }

    /**
     * Check for permissions API anomalies
     */
    async checkPermissionsAsync() {
        try {
            const notifPerm = await navigator.permissions.query({ name: 'notifications' });

            // Check consistency with Notification API
            if (typeof Notification !== 'undefined' &&
                notifPerm.state !== Notification.permission) {
                this.checks.permissionInconsistency = true;
                this.score += 20;
            }
        } catch (e) {
            // Some browsers don't support all queries
        }
    }

    /**
     * Check navigator properties for inconsistencies
     */
    checkNavigatorInconsistencies() {
        const issues = [];

        // Platform vs userAgent mismatch
        const uaPlatform = /Win/.test(navigator.userAgent) ? 'Win32' :
            /Mac/.test(navigator.userAgent) ? 'MacIntel' :
                /Linux/.test(navigator.userAgent) ? 'Linux x86_64' : '';

        if (uaPlatform && navigator.platform !== uaPlatform) {
            issues.push('platform-mismatch');
        }

        // Language inconsistencies
        if (navigator.language && navigator.languages &&
            !navigator.languages.includes(navigator.language)) {
            issues.push('language-mismatch');
        }

        // Suspicious hardware values
        if (navigator.hardwareConcurrency > 32 || navigator.hardwareConcurrency === 0) {
            issues.push('suspicious-cpu');
        }

        if (navigator.deviceMemory &&
            (navigator.deviceMemory > 32 || navigator.deviceMemory < 0.25)) {
            issues.push('suspicious-memory');
        }

        // Vendor mismatch
        const expectedVendor = /Chrome/.test(navigator.userAgent) ? 'Google Inc.' :
            /Safari/.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent) ? 'Apple Computer, Inc.' : '';

        if (expectedVendor && navigator.vendor !== expectedVendor) {
            issues.push('vendor-mismatch');
        }

        this.checks.navigatorIssues = issues;

        if (issues.length > 0) {
            this.score += Math.min(issues.length * 10, this.config.navigatorWeight);
        }

        return issues;
    }

    /**
     * Check for automation framework artifacts
     */
    checkAutomationArtifacts() {
        const artifacts = [];

        // Selenium
        if (window._Selenium_IDE_Recorder ||
            window.document.documentElement.getAttribute('selenium') ||
            window.document.documentElement.getAttribute('driver')) {
            artifacts.push('selenium');
        }

        // Chrome automation
        if (window.cdc_adoQpoasnfa76pfcZLmcfl_Array ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Promise ||
            window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol) {
            artifacts.push('chrome-automation');
        }

        // Puppeteer
        if (navigator.webdriver === undefined && /HeadlessChrome/.test(navigator.userAgent)) {
            artifacts.push('puppeteer');
        }

        // Playwright
        if (window.__playwright__ ||
            window.__pw_manual ||
            window.__PW_inspect) {
            artifacts.push('playwright');
        }

        // Nightmare
        if (window.__nightmare) {
            artifacts.push('nightmare');
        }

        this.checks.automationArtifacts = artifacts;

        if (artifacts.length > 0) {
            this.score += 50; // High confidence bot
        }

        return artifacts;
    }

    /**
     * Generate comprehensive browser fingerprint
     */
    async generateFingerprint() {
        this.fingerprint = {
            canvas: await this.getCanvasFingerprint(),
            webgl: this.getWebGLFingerprint(),
            audio: this.getAudioFingerprint(),
            fonts: this.getFontFingerprint(),
            screen: this.getScreenFingerprint(),
            browser: this.getBrowserFingerprint()
        };

        // Check for suspicious fingerprint patterns
        if (!this.fingerprint.canvas || !this.fingerprint.webgl) {
            this.score += 15; // Missing expected capabilities
        }

        // Canvas/WebGL hash can be checked against known bot patterns
        // (would require server-side database)

        return this.fingerprint;
    }

    /**
     * Canvas fingerprinting
     */
    async getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');

            if (!ctx) return null;

            // Draw text with specific styling
            ctx.textBaseline = 'top';
            ctx.font = '14px "Arial"';
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('abcdefghijklmnopqrstuvwxyz0123456789', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 4, 17);

            // Get data URL
            const dataURL = canvas.toDataURL();

            // Simple hash
            return this.simpleHash(dataURL);
        } catch (e) {
            return null;
        }
    }

    /**
     * WebGL fingerprinting
     */
    getWebGLFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

            if (!gl) return null;

            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');

            if (!debugInfo) return null;

            return {
                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL),
                version: gl.getParameter(gl.VERSION),
                shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                extensionCount: gl.getSupportedExtensions().length
            };
        } catch (e) {
            return null;
        }
    }

    /**
     * Audio context fingerprinting
     */
    getAudioFingerprint() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) return null;

            const context = new AudioContext();
            const fingerprint = {
                sampleRate: context.sampleRate,
                state: context.state,
                baseLatency: context.baseLatency,
                outputLatency: context.outputLatency
            };

            context.close();
            return fingerprint;
        } catch (e) {
            return null;
        }
    }

    /**
     * Font detection fingerprinting
     */
    getFontFingerprint() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Verdana', 'Times New Roman', 'Courier New',
            'Georgia', 'Palatino', 'Garamond', 'Comic Sans MS',
            'Trebuchet MS', 'Impact'
        ];

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        const testString = 'mmmmmmmmmmlli';
        const baseSizes = {};
        const detectedFonts = [];

        // Get baseline sizes
        baseFonts.forEach(font => {
            ctx.font = `72px ${font}`;
            baseSizes[font] = ctx.measureText(testString).width;
        });

        // Test each font
        testFonts.forEach(font => {
            baseFonts.forEach(baseFont => {
                ctx.font = `72px ${font}, ${baseFont}`;
                const size = ctx.measureText(testString).width;

                if (size !== baseSizes[baseFont]) {
                    if (!detectedFonts.includes(font)) {
                        detectedFonts.push(font);
                    }
                }
            });
        });

        return detectedFonts;
    }

    /**
     * Screen fingerprinting
     */
    getScreenFingerprint() {
        return {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            devicePixelRatio: window.devicePixelRatio,
            orientation: screen.orientation?.type
        };
    }

    /**
     * Browser properties fingerprinting
     */
    getBrowserFingerprint() {
        return {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            language: navigator.language,
            languages: navigator.languages,
            cookieEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            hardwareConcurrency: navigator.hardwareConcurrency,
            deviceMemory: navigator.deviceMemory,
            maxTouchPoints: navigator.maxTouchPoints,
            vendor: navigator.vendor,
            vendorSub: navigator.vendorSub,
            productSub: navigator.productSub,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset()
        };
    }

    // REMOVED: startBehaviorTracking and waitForBehavior
    // Behavior tracking was causing false positives for real humans

    /**
     * Calculate final score based on definitive bot signals only
     * REMOVED: Behavior and timing checks that falsely flag real humans
     */
    calculateScore() {
        // Store behavior data for logging only, no scoring
        this.checks.behaviorScore = 0;

        // REMOVED: Behavioral scoring - real humans may not interact before redirect
        // REMOVED: Timing analysis - fast loading doesn't indicate bot
        // REMOVED: Resource timing - not a reliable bot signal

        // Score is now based only on definitive signals from:
        // - CDP detection (detectCDP)
        // - WebDriver flag (detectWebDriver)  
        // - Headless browser signals (detectHeadless)
        // - Automation artifacts (checkAutomationArtifacts)
    }

    /**
     * Simple hash function
     */
    simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    /**
     * Get human-readable result
     */
    getResult() {
        const confidence = Math.min(Math.round((this.score / 150) * 100), 100);

        return {
            isBot: this.score >= this.config.threshold,
            confidence: confidence,
            score: this.score,
            verdict: this.score >= 100 ? 'Definite Bot' :
                this.score >= 70 ? 'Likely Bot' :
                    this.score >= 40 ? 'Suspicious' :
                        'Likely Human',
            details: this.checks,
            behaviors: this.behaviors
        };
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AdvancedBotDetector;
}
