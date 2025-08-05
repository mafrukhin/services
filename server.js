const express = require('express');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Konfigurasi
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET_KEY;
const HUMAN_URL = process.env.HUMAN_REDIRECT_URL;
const BOT_URL = process.env.BOT_REDIRECT_URL;

// Database in-memory untuk tracking
const userSessions = new Map();
const suspiciousIPs = new Set();

// Bot detection patterns
const BOT_USER_AGENTS = [
  /bot/i, /crawler/i, /spider/i, /scraper/i, /headless/i,
  /phantom/i, /selenium/i, /puppeteer/i, /playwright/i,
  /curl/i, /wget/i, /python/i, /java/i, /go-http/i,
  /apache-httpclient/i, /okhttp/i, /node/i
];

const HUMAN_USER_AGENTS = [
  /Mozilla.*Chrome/i, /Mozilla.*Firefox/i, /Mozilla.*Safari/i,
  /Mozilla.*Edge/i, /Mozilla.*Opera/i
];

// Google Apps Script logging function
async function logToGoogleAppsScript(data) {
  try {
    const { zonaId, clickId, country, userAgent, ip, isBot, captchaScore, redirectUrl, detectionLayer, riskScore } = data;
    
    const googleLogUrl = `https://script.google.com/macros/s/AKfycbzRyPLipIelQSGK98hA0MklyGHHW0MFYP0TFVuXL6K95v1GvD8d9kB96vda_4qKas61Rg/exec`;
    
    // Pastikan semua parameter ada dan dalam format yang benar
    const params = new URLSearchParams({
      zoneid: zonaId || 'Unknown',
      subzone_id: clickId || 'Unknown',
      country: country || 'Unknown',
      level: detectionLayer || 'Unknown',
      timestamp: new Date().toISOString(),
      user_agent: (userAgent || 'Unknown').substring(0, 500), // Batasi panjang UA
      ip_address: ip || 'Unknown',
      is_bot: isBot ? '1' : '0',
      captcha_score: captchaScore || 'Unknown',
      redirect_url: redirectUrl || 'Unknown',
      detection_layer: detectionLayer || 'Unknown',
      risk_score: (riskScore || 0).toString()
    });

    const fullUrl = `${googleLogUrl}?${params.toString()}`;
    
    console.log('📊 Logging to Google Apps Script...');
    console.log('📋 Data being sent:', {
      zoneid: zonaId,
      subzone_id: clickId,
      country: country,
      detection_layer: detectionLayer,
      is_bot: isBot ? 'BOT' : 'HUMAN',
      risk_score: riskScore
    });
    
    const response = await axios.get(fullUrl, {
      timeout: 15000, // Increased timeout
      headers: {
        'User-Agent': 'Bot-Detection-Service/2.0'
      }
    });
    
    console.log('✅ Data berhasil dikirim ke Google Apps Script');
    console.log('📄 Response:', response.data);
    
    return { success: true, response: response.data };
    
  } catch (error) {
    console.error('❌ Error mengirim data ke Google Apps Script:');
    console.error('🔍 Error details:', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      statusText: error.response?.statusText
    });
    
    if (error.code === 'ECONNABORTED') {
      console.error('⏱️ Request timeout - Google Apps Script lambat merespons');
    } else if (error.response) {
      console.error('📋 Response data:', error.response.data);
    }
    
    return { success: false, error: error.message };
  }
}

// Layer 1: Basic Bot Detection
function detectBotLayer1(userAgent, ip, headers) {
  let riskScore = 0;
  let reasons = [];

  // Check User-Agent
  if (!userAgent) {
    riskScore += 50;
    reasons.push('Missing User-Agent');
  } else {
    // Check for bot patterns
    for (const pattern of BOT_USER_AGENTS) {
      if (pattern.test(userAgent)) {
        riskScore += 80;
        reasons.push('Bot User-Agent detected');
        break;
      }
    }

    // Check for human patterns
    let hasHumanUA = false;
    for (const pattern of HUMAN_USER_AGENTS) {
      if (pattern.test(userAgent)) {
        hasHumanUA = true;
        break;
      }
    }
    
    if (!hasHumanUA) {
      riskScore += 30;
      reasons.push('Non-standard User-Agent');
    }
  }

  // Check for suspicious headers
  const acceptHeader = headers.accept || '';
  if (!acceptHeader.includes('text/html')) {
    riskScore += 20;
    reasons.push('Missing HTML accept header');
  }

  const acceptLanguage = headers['accept-language'];
  if (!acceptLanguage) {
    riskScore += 15;
    reasons.push('Missing Accept-Language');
  }

  const acceptEncoding = headers['accept-encoding'];
  if (!acceptEncoding) {
    riskScore += 15;
    reasons.push('Missing Accept-Encoding');
  }

  // Check for automation tools
  if (headers['x-requested-with'] || headers['x-automation']) {
    riskScore += 60;
    reasons.push('Automation headers detected');
  }

  // Check for suspicious IP behavior
  if (suspiciousIPs.has(ip)) {
    riskScore += 40;
    reasons.push('Suspicious IP activity');
  }

  return {
    riskScore,
    reasons,
    isBot: riskScore >= 70
  };
}

// Layer 2: Behavioral Analysis
function detectBotLayer2(sessionId, ip) {
  let riskScore = 0;
  let reasons = [];

  const session = userSessions.get(sessionId);
  if (!session) {
    // First visit
    userSessions.set(sessionId, {
      ip,
      visits: 1,
      firstVisit: Date.now(),
      lastVisit: Date.now(),
      pageViews: 1
    });
  } else {
    const now = Date.now();
    const timeDiff = now - session.lastVisit;
    
    session.visits++;
    session.lastVisit = now;
    session.pageViews++;

    // Check for rapid requests
    if (timeDiff < 1000) { // Less than 1 second
      riskScore += 40;
      reasons.push('Rapid successive requests');
    }

    // check for too many visits
    if (session.visits > 10) {
      riskScore += 30;
      reasons.push('Excessive visits');
      suspiciousIPs.add(ip);
    }

    // Check for IP mismatch
    if (session.ip !== ip) {
      riskScore += 50;
      reasons.push('IP address changed');
    }
  }

  return {
    riskScore,
    reasons,
    isBot: riskScore >= 60
  };
}

// Layer 3: JavaScript Challenge
function generateJSChallenge() {
  const challenges = [
    {
      question: "Calculate: Math.floor(Math.random() * 100) + 50",
      answer: (min, max) => Math.floor(Math.random() * (max - min + 1)) + min,
      check: (answer) => answer >= 50 && answer < 150
    },
    {
      question: "What is the result of: new Date().getFullYear()",
      answer: () => new Date().getFullYear(),
      check: (answer) => answer === new Date().getFullYear()
    },
    {
      question: "Calculate: window.screen.width + window.screen.height",
      answer: () => "dynamic",
      check: (answer) => answer > 500 // Reasonable screen dimension sum
    }
  ];

  const challenge = challenges[Math.floor(Math.random() * challenges.length)];
  return challenge;
}

// Fungsi untuk memverifikasi hCaptcha
async function verifyHCaptcha(token, remoteip) {
  try {
    const response = await axios.post('https://hcaptcha.com/siteverify', 
      `secret=${HCAPTCHA_SECRET}&response=${token}&remoteip=${remoteip}`,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    
    return response.data;
  } catch (error) {
    console.error('Error verifying hCaptcha:', error);
    return { success: false, error: 'verification_failed' };
  }
}

// Route utama - multi-layer detection
app.get('/', async (req, res) => {
  const { ClickId, ZonaId, Country } = req.query;
  
  // Validasi parameter yang diperlukan
  if (!ClickId || !ZonaId || !Country) {
    return res.status(400).json({
      error: 'Missing required parameters: ClickId, ZonaId, Country'
    });
  }

  const userAgent = req.get('User-Agent');
  const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
  const sessionId = req.sessionID || `${clientIP}_${Date.now()}`;

  console.log(`\n🔍 Starting multi-layer bot detection for IP: ${clientIP}`);
  console.log(`User-Agent: ${userAgent}`);

  // LAYER 1: Basic Bot Detection
  console.log('\n🚦 LAYER 1: Basic Bot Detection');
  const layer1Result = detectBotLayer1(userAgent, clientIP, req.headers);
  console.log(`Layer 1 Risk Score: ${layer1Result.riskScore}`);
  console.log(`Layer 1 Reasons:`, layer1Result.reasons);

  if (layer1Result.isBot) {
    console.log('❌ BLOCKED at Layer 1 - Obvious bot detected');
    
    // Log dan redirect langsung ke bot URL
    const logData = {
      clickId: ClickId,
      zonaId: ZonaId,
      country: Country,
      userAgent,
      ip: clientIP,
      isBot: true,
      captchaScore: null,
      redirectUrl: BOT_URL,
      detectionLayer: 'Layer1',
      riskScore: layer1Result.riskScore
    };

    logToGoogleAppsScript(logData).catch(console.error);

    return res.redirect(BOT_URL);
  }

  // LAYER 2: Behavioral Analysis
  console.log('\n🧠 LAYER 2: Behavioral Analysis');
  const layer2Result = detectBotLayer2(sessionId, clientIP);
  console.log(`Layer 2 Risk Score: ${layer2Result.riskScore}`);
  console.log(`Layer 2 Reasons:`, layer2Result.reasons);

  const totalRiskScore = layer1Result.riskScore + layer2Result.riskScore;
  console.log(`\n📊 Total Risk Score: ${totalRiskScore}`);

  if (totalRiskScore >= 100) {
    console.log('❌ BLOCKED at Layer 2 - High risk behavior');
    
    const logData = {
      clickId: ClickId,
      zonaId: ZonaId,
      country: Country,
      userAgent,
      ip: clientIP,
      isBot: true,
      captchaScore: null,
      redirectUrl: BOT_URL,
      detectionLayer: 'Layer2',
      riskScore: totalRiskScore
    };

    logToGoogleAppsScript(logData).catch(console.error);

    return res.redirect(BOT_URL);
  }

  // LAYER 3: JavaScript Challenge + hCaptcha
  console.log('\n🧩 LAYER 3: JavaScript Challenge + hCaptcha');
  
  if (totalRiskScore < 30) {
    console.log('✅ Low risk - Direct approval');
    
    const logData = {
      clickId: ClickId,
      zonaId: ZonaId,
      country: Country,
      userAgent,
      ip: clientIP,
      isBot: false,
      captchaScore: 'low-risk-bypass',
      redirectUrl: HUMAN_URL,
      detectionLayer: 'Layer3-LowRisk',
      riskScore: totalRiskScore
    };

    logToGoogleAppsScript(logData).catch(console.error);

    return res.redirect(HUMAN_URL);
  }

  // Generate JS Challenge
  const jsChallenge = generateJSChallenge();
  
  // Show hCaptcha with enhanced validation
  const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <style>
        body {
            margin: 0;
            padding: 20px;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        
        .header {
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            margin: 0 0 10px 0;
            font-size: 24px;
            font-weight: 600;
        }
        
        .header p {
            color: #666;
            margin: 0;
            font-size: 14px;
        }
        
        .verification-steps {
            margin: 30px 0;
        }
        
        .step {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            transition: all 0.3s ease;
        }
        
        .step.completed {
            background: #d4edda;
            border-color: #c3e6cb;
        }
        
        .step.current {
            background: #fff3cd;
            border-color: #ffeaa7;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .step-title {
            font-weight: 600;
            color: #333;
            margin-bottom: 10px;
        }
        
        .js-challenge {
            background: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
        }
        
        .js-challenge input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 16px;
        }
        
        .captcha-container {
            margin: 20px 0;
            display: flex;
            justify-content: center;
        }
        
        .submit-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 20px;
        }
        
        .submit-btn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .submit-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .status {
            margin: 15px 0;
            padding: 10px;
            border-radius: 6px;
            font-size: 14px;
            display: none;
        }
        
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }
        
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }
        
        .progress-bar {
            width: 100%;
            height: 4px;
            background: #e9ecef;
            border-radius: 2px;
            margin: 20px 0;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            width: 0%;
            transition: width 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Verification</h1>
            <p>Please complete the verification steps below</p>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" id="progressFill"></div>
        </div>
        
        <form id="verificationForm">
            <input type="hidden" name="clickId" value="${ClickId}">
            <input type="hidden" name="zonaId" value="${ZonaId}">
            <input type="hidden" name="country" value="${Country}">
            <input type="hidden" name="sessionId" value="${sessionId}">
            <input type="hidden" name="riskScore" value="${totalRiskScore}">
            
            <div class="verification-steps">
                <!-- Step 1: JS Challenge -->
                <div class="step current" id="step1">
                    <div class="step-title">Step 1: JavaScript Validation</div>
                    <div class="js-challenge">
                        <p>Please solve this simple calculation:</p>
                        <p><strong>What is your current screen width + screen height?</strong></p>
                        <input type="number" id="jsAnswer" name="jsAnswer" placeholder="Enter the result" required>
                    </div>
                </div>
                
                <!-- Step 2: Captcha -->
                <div class="step" id="step2">
                    <div class="step-title">Step 2: Human Verification</div>
                    <div class="captcha-container">
                        <div class="h-captcha" 
                             data-sitekey="${process.env.HCAPTCHA_SITE_KEY}" 
                             data-callback="onCaptchaSuccess"
                             data-error-callback="onCaptchaError">
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="status" id="status"></div>
            
            <button type="submit" class="submit-btn" id="submitBtn" disabled>
                🚀 Complete Verification
            </button>
        </form>
    </div>

    <script>
        let jsValidated = false;
        let captchaValidated = false;
        let captchaToken = null;
        
        // Auto-fill JS challenge
        document.addEventListener('DOMContentLoaded', function() {
            const jsAnswer = window.screen.width + window.screen.height;
            document.getElementById('jsAnswer').value = jsAnswer;
            
            // Validate JS answer immediately
            setTimeout(() => {
                validateJSChallenge();
            }, 1000);
            
            updateProgress();
        });
        
        function validateJSChallenge() {
            const answer = parseInt(document.getElementById('jsAnswer').value);
            const expected = window.screen.width + window.screen.height;
            
            if (Math.abs(answer - expected) <= 10) { // Allow small variance
                jsValidated = true;
                document.getElementById('step1').classList.remove('current');
                document.getElementById('step1').classList.add('completed');
                document.getElementById('step2').classList.add('current');
                showStatus('✅ JavaScript validation passed!', 'success');
                updateProgress();
            } else {
                showStatus('❌ JavaScript validation failed. Please check your answer.', 'error');
            }
        }
        
        function onCaptchaSuccess(token) {
            captchaValidated = true;
            captchaToken = token;
            document.getElementById('step2').classList.remove('current');
            document.getElementById('step2').classList.add('completed');
            showStatus('✅ Human verification completed!', 'success');
            updateProgress();
        }
        
        function onCaptchaError(error) {
            showStatus('❌ Captcha verification failed: ' + error, 'error');
            captchaValidated = false;
            updateProgress();
        }
        
        function updateProgress() {
            let progress = 0;
            if (jsValidated) progress += 50;
            if (captchaValidated) progress += 50;
            
            document.getElementById('progressFill').style.width = progress + '%';
            document.getElementById('submitBtn').disabled = !(jsValidated && captchaValidated);
            
            if (progress === 100) {
                document.getElementById('submitBtn').innerHTML = '🎉 Submit & Continue';
            }
        }
        
        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = message;
            statusDiv.className = 'status ' + type;
            
            if (type === 'error') {
                setTimeout(() => {
                    statusDiv.style.display = 'none';
                }, 5000);
            }
        }
        
        // Form submission
        document.getElementById('verificationForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (!jsValidated || !captchaValidated) {
                showStatus('❌ Please complete all verification steps', 'error');
                return;
            }
            
            showStatus('🔄 Processing verification...', 'success');
            document.getElementById('submitBtn').disabled = true;
            document.getElementById('submitBtn').innerHTML = '⏳ Processing...';
            
            const formData = new FormData(this);
            formData.append('h-captcha-response', captchaToken);
            
            fetch('/verify', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.redirectUrl) {
                    showStatus('✅ Verification successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = data.redirectUrl;
                    }, 1500);
                } else {
                    showStatus('❌ Verification failed: ' + (data.error || 'Unknown error'), 'error');
                    document.getElementById('submitBtn').disabled = false;
                    document.getElementById('submitBtn').innerHTML = '🔄 Retry Verification';
                    
                    // Reset captcha
                    if (typeof hcaptcha !== 'undefined') {
                        hcaptcha.reset();
                    }
                    captchaValidated = false;
                    updateProgress();
                }
            })
            .catch(error => {
                console.error('Fetch error:', error);
                showStatus('❌ Network error. Please try again.', 'error');
                document.getElementById('submitBtn').disabled = false;
                document.getElementById('submitBtn').innerHTML = '🔄 Retry Verification';
            });
        });
        
        // JS Challenge validation on input
        document.getElementById('jsAnswer').addEventListener('input', function() {
            if (this.value) {
                setTimeout(() => validateJSChallenge(), 500);
            }
        });
    </script>
</body>
</html>`;
  
  res.send(html);
});

// Route untuk memverifikasi captcha dan redirect
app.post('/verify', async (req, res) => {
  const { 
    'h-captcha-response': captchaToken, 
    clickId, 
    zonaId, 
    country, 
    sessionId, 
    riskScore,
    jsAnswer 
  } = req.body;
  
  const userAgent = req.get('User-Agent');
  const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;

  console.log('\n🔐 Final verification step');
  console.log(`Risk Score: ${riskScore}`);
  console.log(`JS Answer: ${jsAnswer}`);

  let isBot = false;
  let redirectUrl = HUMAN_URL;
  let captchaScore = null;
  let detectionLayer = 'Layer3-Captcha';

  try {
    // Validate JS Challenge
    const expectedJS = 800; // Approximate screen dimension sum for validation
    const jsAnswerNum = parseInt(jsAnswer);
    
    if (!jsAnswerNum || jsAnswerNum < 500 || jsAnswerNum > 5000) {
      console.log('❌ JS Challenge failed');
      isBot = true;
      redirectUrl = BOT_URL;
      detectionLayer = 'Layer3-JSFailed';
    } else if (!captchaToken) {
      console.log('❌ Missing captcha token');
      isBot = true;
      redirectUrl = BOT_URL;
      detectionLayer = 'Layer3-NoCaptcha';
    } else {
      // Verify hCaptcha
      const captchaResult = await verifyHCaptcha(captchaToken, clientIP);

      if (!captchaResult.success) {
        console.log('❌ Captcha verification failed');
        isBot = true;
        redirectUrl = BOT_URL;
        detectionLayer = 'Layer3-CaptchaFailed';
      } else {
        console.log('✅ All verifications passed - Human confirmed');
        isBot = false;
        redirectUrl = HUMAN_URL;
        captchaScore = captchaResult.score || 'passed';
        detectionLayer = 'Layer3-Success';
      }
    }
  } catch (error) {
    console.error('Error dalam verifikasi:', error);
    isBot = true;
    redirectUrl = BOT_URL;
    detectionLayer = 'Layer3-Error';
  }

  // Siapkan data untuk logging ke Google Apps Script
  const logData = {
    clickId,
    zonaId,
    country,
    userAgent,
    ip: clientIP,
    isBot,
    captchaScore,
    redirectUrl,
    detectionLayer,
    riskScore: riskScore || 0
  };

  // Log ke Google Apps Script
  console.log(`Final Decision: ${isBot ? 'BOT' : 'HUMAN'} -> ${redirectUrl}`);
  logToGoogleAppsScript(logData).catch(error => {
    console.error('Failed to log to Google Apps Script:', error);
  });

  // Response dengan URL redirect
  res.json({
    success: true,
    redirectUrl,
    isBot,
    detectionLayer,
    message: isBot ? 'Bot detected' : 'Human verified'
  });
});

// Route untuk health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    activeSessions: userSessions.size,
    suspiciousIPs: suspiciousIPs.size
  });
});

// Route untuk reset suspicious IPs (admin)
app.post('/admin/reset-suspicious', (req, res) => {
  suspiciousIPs.clear();
  userSessions.clear();
  res.json({ success: true, message: 'Suspicious IPs and sessions cleared' });
});

// Route untuk test Google Apps Script logging
app.get('/test-log', async (req, res) => {
  try {
    const testData = {
      clickId: 'TEST_' + Date.now(),
      zonaId: 'TEST_ZONA',
      country: 'ID',
      userAgent: 'TEST_AGENT',
      ip: '127.0.0.1',
      isBot: false,
      captchaScore: 'test',
      redirectUrl: 'https://test.com',
      detectionLayer: 'Test',
      riskScore: 25
    };
    
    const result = await logToGoogleAppsScript(testData);
    
    res.json({
      success: true,
      message: 'Google Apps Script logging test completed!',
      result,
      testData
    });
    
  } catch (error) {
    console.error('Google Apps Script test error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Multi-layer Bot Detection Service berjalan di port ${PORT}`);
  console.log(`📱 Akses: http://localhost:${PORT}/?ClickId=123&ZonaId=456&Country=ID`);
  console.log(`🧪 Test logging: http://localhost:${PORT}/test-log`);
  console.log(`💊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔧 Reset suspicious: POST http://localhost:${PORT}/admin/reset-suspicious`);
});

module.exports = app;