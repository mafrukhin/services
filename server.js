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
const HUMAN_URL = process.env.HUMAN_REDIRECT_URL || 'https://example.com/human';
const BOT_URL = process.env.BOT_REDIRECT_URL || 'https://example.com/bot';

// Google Apps Script logging function
async function logToGoogleAppsScript(data) {
  try {
    const { zonaId, clickId, country, userAgent, ip, isBot, captchaScore, redirectUrl } = data;
    
    // Construct the Google Apps Script URL with parameters
    const googleLogUrl = `https://script.google.com/macros/s/AKfycbwkrNxaswfcqVieoND3VicnaDZrsHIdy8cJOyMbYmMK6rcozBstWN_jh0A7FRp3033vjA/exec`;
    
    const params = new URLSearchParams({
      zoneid: zonaId || '',
      subzone_id: clickId || '',
      country: country || '',
      timestamp: new Date().toISOString(),
      user_agent: userAgent || '',
      ip_address: ip || '',
      is_bot: isBot ? '1' : '0',
      captcha_score: captchaScore || '',
      redirect_url: redirectUrl || ''
    });

    const fullUrl = `${googleLogUrl}?${params.toString()}`;
    
    console.log('Logging to Google Apps Script...');
    console.log('URL:', fullUrl);
    
    const response = await axios.get(fullUrl, {
      timeout: 10000, // 10 second timeout
      headers: {
        'User-Agent': 'Bot-Detection-Service/1.0'
      }
    });
    
    console.log('✅ Data berhasil dikirim ke Google Apps Script');
    console.log('Response:', response.data);
    
    return { success: true, response: response.data };
    
  } catch (error) {
    console.error('❌ Error mengirim data ke Google Apps Script:');
    console.error('Error message:', error.message);
    
    if (error.code === 'ECONNABORTED') {
      console.error('Request timeout - Google Apps Script mungkin lambat merespons');
    } else if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
    
    return { success: false, error: error.message };
  }
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

// Route utama - menampilkan halaman captcha
app.get('/', (req, res) => {
  const { ClickId, ZonaId, Country } = req.query;
  
  // Validasi parameter yang diperlukan
  if (!ClickId || !ZonaId || !Country) {
    return res.status(400).json({
      error: 'Missing required parameters: ClickId, ZonaId, Country'
    });
  }

  // --- MODE BYPASS UNTUK TESTING ---
  const BYPASS = true; // ubah ke false kalau mau pakai hCaptcha lagi
  
  if (BYPASS) {
    // Mode bypass - langsung redirect tanpa tampilan apapun
    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
</head>
<body>
    <script>
        // Auto submit dalam bypass mode - langsung redirect ke BOT URL
        const formData = new FormData();
        formData.append('clickId', '${ClickId}');
        formData.append('zonaId', '${ZonaId}');
        formData.append('country', '${Country}');
        formData.append('h-captcha-response', 'bypass-mode');

        fetch('/verify', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.href = data.redirectUrl;
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    </script>
</body>
</html>`;
    
    return res.send(html);
  }
  
  // Mode normal - hanya menampilkan hCaptcha tanpa teks atau elemen lain
  const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <style>
        body {
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: transparent;
        }
    </style>
</head>
<body>
    <form id="captchaForm">
        <input type="hidden" name="clickId" value="${ClickId}">
        <input type="hidden" name="zonaId" value="${ZonaId}">
        <input type="hidden" name="country" value="${Country}">
        
        <div class="h-captcha" 
             data-sitekey="${process.env.HCAPTCHA_SITE_KEY}" 
             data-callback="onCaptchaSuccess">
        </div>
    </form>

    <script>
        function onCaptchaSuccess(token) {
            const formData = new FormData(document.getElementById('captchaForm'));
            formData.append('h-captcha-response', token);
            
            fetch('/verify', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = data.redirectUrl;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                hcaptcha.reset();
            });
        }
    </script>
</body>
</html>`;
  
  res.send(html);
});

// Route untuk memverifikasi captcha dan redirect
app.post('/verify', async (req, res) => {
  const { 'h-captcha-response': captchaToken, clickId, zonaId, country } = req.body;
  const userAgent = req.get('User-Agent');
  const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;

  // --- MODE BYPASS UNTUK TESTING ---
  const BYPASS = false; // ubah ke false kalau mau pakai hCaptcha lagi
  let isBot = false;
  let redirectUrl = HUMAN_URL;
  let captchaScore = null;

  if (BYPASS) {
    console.log('[BYPASS MODE] Melewati verifikasi hCaptcha');
    console.log('Data yang diterima:', { clickId, zonaId, country, userAgent, clientIP });
    
    // Dalam bypass mode, SELALU anggap sebagai BOT dan redirect ke BOT URL
    isBot = true;
    redirectUrl = BOT_URL;
    captchaScore = 'bypass-mode';
  } else {
    // Mode normal dengan hCaptcha
    // Validasi captcha token
    if (!captchaToken) {
      return res.json({
        success: false,
        error: 'Captcha tidak valid'
      });
    }

    try {
      // Verifikasi hCaptcha
      const captchaResult = await verifyHCaptcha(captchaToken, clientIP);

      if (!captchaResult.success) {
        // Jika captcha gagal, anggap sebagai bot
        isBot = true;
        redirectUrl = BOT_URL;
      } else {
        // Jika captcha berhasil, anggap sebagai manusia
        isBot = false;
        redirectUrl = HUMAN_URL;
        captchaScore = captchaResult.score || null;
      }
    } catch (error) {
      console.error('Error dalam verifikasi:', error);
      
      // Jika ada error, anggap sebagai bot untuk keamanan
      isBot = true;
      redirectUrl = BOT_URL;
    }
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
    redirectUrl
  };

  // Log ke Google Apps Script (async, tidak menunggu)
  console.log('Mencoba mengirim log ke Google Apps Script:', logData);
  logToGoogleAppsScript(logData).catch(error => {
    console.error('Failed to log to Google Apps Script:', error);
  });

  // Response dengan URL redirect
  console.log(`Redirecting to: ${redirectUrl} (isBot: ${isBot})`);
  res.json({
    success: true,
    redirectUrl,
    isBot
  });
});

// Route untuk health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Route untuk test Google Apps Script logging
app.get('/test-log', async (req, res) => {
  try {
    console.log('Testing Google Apps Script logging...');
    
    const testData = {
      clickId: 'TEST_' + Date.now(),
      zonaId: 'TEST_ZONA',
      country: 'ID',
      userAgent: 'TEST_AGENT',
      ip: '127.0.0.1',
      isBot: false,
      captchaScore: 'test',
      redirectUrl: 'https://test.com'
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
      error: error.message,
      stack: error.stack
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
  console.log(`Bot Detection Service berjalan di port ${PORT}`);
  console.log(`Akses: http://localhost:${PORT}/?ClickId=123&ZonaId=456&Country=ID`);
  console.log(`Test logging: http://localhost:${PORT}/test-log`);
});

module.exports = app;