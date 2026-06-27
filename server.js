const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ===== ADVANCED DATABASE =====
const users = {};
const sessions = {};
const orders = {};
const transactions = {};
const rateLimits = {};
const emailVerifications = {};
const twoFATokens = {};
const adminLogs = {};

// ===== EMAIL CONFIG (Gunakan Gmail, SendGrid, atau SMTP lain) =====
// NOTE: Untuk Gmail, gunakan App Password, bukan password biasa
// https://myaccount.google.com/apppasswords
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASSWORD || 'your-app-password'
  }
});

// ===== PAYMENT CONFIG (Midtrans) =====
const MIDTRANS_SERVER_KEY = process.env.MIDTRANS_SERVER_KEY;
const MIDTRANS_CLIENT_KEY = process.env.MIDTRANS_CLIENT_KEY;
const MIDTRANS_API_URL = 'https://app.sandbox.midtrans.com/snap/v1/transactions';

// ===== SMSCode CONFIG =====
const API_KEY = process.env.API_KEY;
const BASE_URL = "https://api.smscode.gg/v1";
const HEADERS = { "Authorization": `Bearer ${API_KEY}` };

// ===== UTILITY FUNCTIONS =====

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + process.env.SALT || 'salt123').digest('hex');
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function generateUserId() {
  return 'user_' + crypto.randomBytes(8).toString('hex');
}

function generateVerificationToken() {
  return crypto.randomBytes(16).toString('hex');
}

function generate2FAToken() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6 digit
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password) {
  return password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password);
}

function authenticateSession(req) {
  const sessionId = req.headers['x-session-id'];
  if (!sessionId || !sessions[sessionId]) return null;
  
  const session = sessions[sessionId];
  if (session.expiresAt < Date.now()) {
    delete sessions[sessionId];
    return null;
  }
  
  return session.userId;
}

function logAdminAction(userId, action, details) {
  const logId = 'log_' + Date.now();
  adminLogs[logId] = {
    userId,
    action,
    details,
    timestamp: new Date().toISOString(),
    ip: details.ip || 'unknown'
  };
}

function checkRateLimit(userId, action = 'buy') {
  const now = Date.now();
  if (!rateLimits[userId]) {
    rateLimits[userId] = {};
  }
  
  const userLimit = rateLimits[userId];
  
  if (!userLimit[action]) {
    userLimit[action] = { count: 1, resetTime: now };
    return true;
  }
  
  const limit = userLimit[action];
  const timePassed = now - limit.resetTime;
  
  // Reset per 60 detik
  if (timePassed > 60000) {
    limit.count = 1;
    limit.resetTime = now;
    return true;
  }
  
  // Max limit per action
  const maxLimits = {
    buy: 5,
    login: 10,
    register: 3,
    topup: 10
  };
  
  if (limit.count >= maxLimits[action]) {
    return false;
  }
  
  limit.count++;
  return true;
}

async function sendEmail(to, subject, htmlContent) {
  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      html: htmlContent
    });
    console.log(`✓ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('Email error:', error);
    return false;
  }
}

async function createMidtransPayment(userId, amount) {
  try {
    const user = users[userId];
    const auth = Buffer.from(MIDTRANS_SERVER_KEY + ':').toString('base64');
    
    const payload = {
      transaction_details: {
        order_id: `ORDER-${userId}-${Date.now()}`,
        gross_amount: amount
      },
      customer_details: {
        email: user.email,
        first_name: user.email.split('@')[0]
      },
      item_details: [
        {
          id: 'TOPUP',
          price: amount,
          quantity: 1,
          name: `SMSCode Top-up - Rp ${amount.toLocaleString('id-ID')}`
        }
      ]
    };

    const response = await axios.post(MIDTRANS_API_URL, payload, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json'
      }
    });

    return response.data.token;
  } catch (error) {
    console.error('Midtrans error:', error.response?.data || error.message);
    return null;
  }
}

// ===== ENDPOINTS =====

// 1. REGISTER dengan Email Verification
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, fullName } = req.body;
    
    // Validasi
    if (!email || !password || !fullName) {
      return res.status(400).json({ success: false, error: "Semua field harus diisi" });
    }
    
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, error: "Email tidak valid" });
    }
    
    // Password lebih strict: min 8 char, harus ada uppercase & number
    if (!isValidPassword(password)) {
      return res.status(400).json({ 
        success: false, 
        error: "Password minimal 8 karakter, harus ada huruf besar & angka (contoh: Password123)" 
      });
    }
    
    // Cek email duplikat
    if (Object.values(users).find(u => u.email === email)) {
      return res.status(400).json({ success: false, error: "Email sudah terdaftar" });
    }
    
    // Buat user
    const userId = generateUserId();
    const verificationToken = generateVerificationToken();
    
    users[userId] = {
      email,
      password_hash: hashPassword(password),
      fullName,
      saldo: 0,
      createdAt: new Date().toISOString(),
      totalOrders: 0,
      totalSpent: 0,
      verified: false,
      twoFAEnabled: false,
      lastLogin: null,
      loginAttempts: 0,
      loginLocked: false
    };
    
    emailVerifications[userId] = {
      token: verificationToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + (24 * 60 * 60 * 1000) // 24 jam
    };
    
    // Kirim email verifikasi
    const verificationLink = `http://localhost:${process.env.PORT || 3000}/verify?token=${verificationToken}&userId=${userId}`;
    const emailHtml = `
      <h2>Verifikasi Email SMSCode</h2>
      <p>Halo ${fullName},</p>
      <p>Silakan klik link di bawah untuk verifikasi email Anda:</p>
      <a href="${verificationLink}" style="padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px;">
        Verifikasi Email
      </a>
      <p>Atau copy link ini: ${verificationLink}</p>
      <p>Link berlaku 24 jam.</p>
      <p>Jika Anda tidak membuat akun ini, abaikan email ini.</p>
    `;
    
    await sendEmail(email, 'Verifikasi Email SMSCode', emailHtml);
    
    res.json({ 
      success: true, 
      message: "Akun dibuat! Silakan verifikasi email Anda.",
      userId
    });
    
    logAdminAction(userId, 'register', { email });
    
  } catch (error) {
    console.error('Register error:', error.message);
    res.status(500).json({ success: false, error: "Gagal register" });
  }
});

// 2. VERIFY EMAIL
app.get('/api/auth/verify-email', (req, res) => {
  try {
    const { token, userId } = req.query;
    
    if (!token || !userId) {
      return res.status(400).json({ success: false, error: "Token atau userId tidak valid" });
    }
    
    const verification = emailVerifications[userId];
    if (!verification || verification.token !== token) {
      return res.status(400).json({ success: false, error: "Token tidak valid" });
    }
    
    if (verification.expiresAt < Date.now()) {
      return res.status(400).json({ success: false, error: "Token sudah expired" });
    }
    
    // Mark as verified
    users[userId].verified = true;
    delete emailVerifications[userId];
    
    res.json({ success: true, message: "✓ Email terverifikasi! Silakan login." });
    
    logAdminAction(userId, 'verify_email', {});
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal verifikasi" });
  }
});

// 3. LOGIN dengan Rate Limiting & Brute Force Protection
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, error: "Email dan password harus diisi" });
    }
    
    // Cari user
    const userId = Object.keys(users).find(id => users[id].email === email);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Email atau password salah" });
    }
    
    const user = users[userId];
    
    // Cek brute force
    if (user.loginLocked && user.loginLockedUntil > Date.now()) {
      return res.status(429).json({ success: false, error: "Akun terkunci. Coba lagi dalam 15 menit." });
    }
    
    // Cek password
    if (user.password_hash !== hashPassword(password)) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      
      // Lock account setelah 5 attempt gagal
      if (user.loginAttempts >= 5) {
        user.loginLocked = true;
        user.loginLockedUntil = Date.now() + (15 * 60 * 1000); // 15 menit
      }
      
      return res.status(401).json({ 
        success: false, 
        error: `Email atau password salah (${user.loginAttempts}/5)` 
      });
    }
    
    // Reset failed attempts
    user.loginAttempts = 0;
    user.loginLocked = false;
    
    // Cek email verified
    if (!user.verified) {
      return res.status(403).json({ success: false, error: "Silakan verifikasi email terlebih dahulu" });
    }
    
    // Generate session
    const sessionId = generateSessionId();
    sessions[sessionId] = {
      userId,
      expiresAt: Date.now() + (24 * 60 * 60 * 1000),
      createdAt: Date.now()
    };
    
    user.lastLogin = new Date().toISOString();
    
    // Jika 2FA enabled, kirim token
    if (user.twoFAEnabled) {
      const token2FA = generate2FAToken();
      twoFATokens[userId] = {
        token: token2FA,
        expiresAt: Date.now() + (5 * 60 * 1000) // 5 menit
      };
      
      await sendEmail(user.email, 'Kode 2FA Anda', `<h2>Kode 2FA: ${token2FA}</h2><p>Berlaku 5 menit.</p>`);
      
      return res.json({ 
        success: true, 
        needsAuth: true,
        message: "Kode 2FA sudah dikirim ke email Anda"
      });
    }
    
    res.json({ 
      success: true, 
      sessionId,
      user: {
        email: user.email,
        fullName: user.fullName,
        saldo: user.saldo,
        totalOrders: user.totalOrders
      }
    });
    
    logAdminAction(userId, 'login', { email });
    
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ success: false, error: "Gagal login" });
  }
});

// 4. VERIFY 2FA
app.post('/api/auth/verify-2fa', (req, res) => {
  try {
    const { email, code } = req.body;
    
    const userId = Object.keys(users).find(id => users[id].email === email);
    if (!userId) {
      return res.status(401).json({ success: false, error: "User tidak ditemukan" });
    }
    
    const token2FA = twoFATokens[userId];
    if (!token2FA || token2FA.token !== code) {
      return res.status(401).json({ success: false, error: "Kode 2FA tidak valid" });
    }
    
    if (token2FA.expiresAt < Date.now()) {
      return res.status(401).json({ success: false, error: "Kode 2FA sudah expired" });
    }
    
    delete twoFATokens[userId];
    
    // Create session
    const sessionId = generateSessionId();
    sessions[sessionId] = {
      userId,
      expiresAt: Date.now() + (24 * 60 * 60 * 1000)
    };
    
    res.json({ 
      success: true, 
      sessionId,
      user: {
        email: users[userId].email,
        fullName: users[userId].fullName,
        saldo: users[userId].saldo
      }
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal verifikasi 2FA" });
  }
});

// 5. LOGOUT
app.post('/api/auth/logout', (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) delete sessions[sessionId];
    
    res.json({ success: true, message: "Logout berhasil" });
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal logout" });
  }
});

// 6. GET USER PROFILE
app.get('/api/user/profile', (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    const user = users[userId];
    res.json({ 
      success: true, 
      user: {
        email: user.email,
        fullName: user.fullName,
        saldo: user.saldo,
        totalOrders: user.totalOrders,
        totalSpent: user.totalSpent,
        createdAt: user.createdAt,
        verified: user.verified,
        twoFAEnabled: user.twoFAEnabled,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch profile" });
  }
});

// 7. ENABLE 2FA
app.post('/api/user/enable-2fa', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    users[userId].twoFAEnabled = true;
    
    const emailHtml = `
      <h2>2FA Diaktifkan</h2>
      <p>Two-Factor Authentication telah diaktifkan untuk akun Anda.</p>
      <p>Anda akan diminta untuk memasukkan kode verifikasi setiap kali login.</p>
    `;
    
    await sendEmail(users[userId].email, '2FA Diaktifkan', emailHtml);
    
    res.json({ success: true, message: "2FA berhasil diaktifkan" });
    
    logAdminAction(userId, 'enable_2fa', {});
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal aktivasi 2FA" });
  }
});

// 8. DISABLE 2FA
app.post('/api/user/disable-2fa', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    users[userId].twoFAEnabled = false;
    
    res.json({ success: true, message: "2FA berhasil dinonaktifkan" });
    
    logAdminAction(userId, 'disable_2fa', {});
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal nonaktifkan 2FA" });
  }
});

// 9. REQUEST PAYMENT TOKEN (Midtrans)
app.post('/api/payment/request-token', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    if (!checkRateLimit(userId, 'topup')) {
      return res.status(429).json({ success: false, error: "Terlalu banyak request top-up. Tunggu sebentar." });
    }
    
    const { amount } = req.body;
    
    if (!amount || amount < 10000 || amount > 10000000) {
      return res.status(400).json({ success: false, error: "Nominal harus Rp 10.000 - Rp 10.000.000" });
    }
    
    // Create Midtrans payment
    const token = await createMidtransPayment(userId, amount);
    
    if (!token) {
      return res.status(500).json({ success: false, error: "Gagal membuat payment token" });
    }
    
    // Simpan transaction pending
    const transactionId = 'txn_' + Date.now();
    transactions[transactionId] = {
      userId,
      amount,
      status: 'pending',
      paymentToken: token,
      createdAt: new Date().toISOString()
    };
    
    res.json({ 
      success: true, 
      token,
      clientKey: MIDTRANS_CLIENT_KEY,
      transactionId
    });
    
  } catch (error) {
    console.error('Payment error:', error.message);
    res.status(500).json({ success: false, error: "Gagal request payment" });
  }
});

// 10. CONFIRM PAYMENT (Webhook dari Midtrans)
app.post('/api/payment/callback', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const notificationBody = req.body;
    const hash = crypto
      .createHash('sha512')
      .update(notificationBody.order_id + notificationBody.status_code + notificationBody.gross_amount + MIDTRANS_SERVER_KEY)
      .digest('hex');

    // Verifikasi signature (untuk security)
    if (hash !== notificationBody.signature_key) {
      return res.status(401).json({ success: false, error: "Invalid signature" });
    }

    // Parse order_id untuk dapat userId
    const [, userId] = notificationBody.order_id.split('-');

    if (notificationBody.transaction_status === 'settlement') {
      // Payment berhasil
      users[userId].saldo += parseInt(notificationBody.gross_amount);
      
      const transaction = Object.values(transactions).find(t => t.userId === userId && t.status === 'pending');
      if (transaction) {
        transaction.status = 'completed';
        transaction.completedAt = new Date().toISOString();
      }

      // Kirim email konfirmasi
      const emailHtml = `
        <h2>✓ Top-up Berhasil</h2>
        <p>Top-up sebesar Rp ${parseInt(notificationBody.gross_amount).toLocaleString('id-ID')} telah dikonfirmasi.</p>
        <p>Saldo Anda sekarang: Rp ${users[userId].saldo.toLocaleString('id-ID')}</p>
      `;
      
      sendEmail(users[userId].email, 'Top-up Berhasil', emailHtml);
      
      logAdminAction(userId, 'payment_success', { amount: notificationBody.gross_amount });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Callback error:', error.message);
    res.status(500).json({ success: false, error: "Gagal process callback" });
  }
});

// 11. TOP-UP (Legacy - untuk testing tanpa payment)
app.post('/api/user/topup', (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    const { amount } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, error: "Nominal tidak valid" });
    }
    
    users[userId].saldo += amount;
    
    res.json({ 
      success: true, 
      message: `Top-up Rp ${amount.toLocaleString('id-ID')} berhasil!`,
      saldoBaru: users[userId].saldo
    });
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal top-up" });
  }
});

// 12. GET CATALOG
app.get('/api/catalog/countries', async (req, res) => {
  try {
    const response = await axios.get(`${BASE_URL}/catalog/countries`, { headers: HEADERS });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch negara" });
  }
});

app.get('/api/catalog/services', async (req, res) => {
  try {
    const { country_id } = req.query;
    if (!country_id) {
      return res.status(400).json({ success: false, error: "country_id harus diberikan" });
    }
    
    const response = await axios.get(`${BASE_URL}/catalog/services?country_id=${country_id}`, { headers: HEADERS });
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch layanan" });
  }
});

app.get('/api/catalog/products', async (req, res) => {
  try {
    const { country_id, platform_id, limit = 10, page = 1 } = req.query;
    
    if (!country_id || !platform_id) {
      return res.status(400).json({ success: false, error: "country_id dan platform_id harus diberikan" });
    }
    
    const response = await axios.get(`${BASE_URL}/catalog/products`, {
      params: {
        country_id: parseInt(country_id),
        platform_id: parseInt(platform_id),
        limit: Math.min(parseInt(limit), 100),
        page: Math.max(parseInt(page), 1)
      },
      headers: HEADERS
    });
    
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch produk" });
  }
});

// 13. BUY NUMBER (dengan validasi lengkap)
app.post('/api/buy', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Silakan login terlebih dahulu" });
    }
    
    if (!checkRateLimit(userId, 'buy')) {
      return res.status(429).json({ success: false, error: "Terlalu banyak request. Tunggu 60 detik." });
    }
    
    const { product_id } = req.body;
    if (!product_id) {
      return res.status(400).json({ success: false, error: "product_id harus diberikan" });
    }
    
    const user = users[userId];
    
    if (user.saldo <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: "Saldo tidak cukup. Silakan top-up.",
        saldoSekarang: user.saldo
      });
    }
    
    // Buy from SMSCode
    const response = await axios.post(
      `${BASE_URL}/orders/create`,
      { product_id: parseInt(product_id), quantity: 1 },
      { 
        headers: {
          ...HEADERS,
          "Idempotency-Key": `order-${userId}-${Date.now()}`
        }
      }
    );

    const orderData = response.data.data.orders[0];
    const harga = orderData.amount || 15000;
    
    // Kurangi saldo
    user.saldo -= harga;
    user.totalOrders++;
    user.totalSpent += harga;
    
    // Simpan order
    orders[orderData.id] = {
      userId,
      phone: orderData.phone_number,
      status: 'waiting',
      harga,
      createdAt: new Date().toISOString(),
      expiresAt: orderData.expires_at
    };
    
    res.json({ 
      success: true, 
      orderId: orderData.id,
      phone: orderData.phone_number,
      harga: harga.toLocaleString('id-ID'),
      saldoSisa: user.saldo
    });
    
    logAdminAction(userId, 'buy_number', { phone: orderData.phone_number, harga });

  } catch (error) {
    console.error('Buy error:', error.response?.data || error.message);
    const statusCode = error.response?.status || 500;
    const errorMsg = error.response?.data?.error?.message || "Gagal membeli nomor";
    res.status(statusCode).json({ success: false, error: errorMsg });
  }
});

// 14. CEK OTP
app.get('/api/check/:orderId', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    const orderId = req.params.orderId;
    
    if (orders[orderId] && orders[orderId].userId !== userId) {
      return res.status(403).json({ success: false, error: "Akses ditolak" });
    }
    
    const response = await axios.get(`${BASE_URL}/orders/active`, { headers: HEADERS });
    const targetOrder = response.data.data.find(o => o.id == orderId);

    if (targetOrder && targetOrder.status === 'OTP_RECEIVED') {
      if (orders[orderId]) {
        orders[orderId].otp = targetOrder.otp_code;
        orders[orderId].status = 'otp_received';
      }
      
      res.json({ 
        success: true, 
        otp: targetOrder.otp_code
      });
    } else if (targetOrder && targetOrder.status === 'ACTIVE') {
      res.json({ 
        success: false, 
        otp: null,
        message: "OTP belum diterima"
      });
    } else {
      res.json({ 
        success: false, 
        otp: null,
        message: "Order tidak ditemukan"
      });
    }
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal cek OTP" });
  }
});

// 15. CANCEL ORDER
app.post('/api/cancel/:orderId', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    const { orderId } = req.params;
    
    if (orders[orderId] && orders[orderId].userId !== userId) {
      return res.status(403).json({ success: false, error: "Akses ditolak" });
    }
    
    await axios.post(
      `${BASE_URL}/orders/cancel`,
      { id: parseInt(orderId) },
      { headers: HEADERS }
    );

    const refundAmount = orders[orderId]?.harga || 0;
    if (refundAmount > 0) {
      users[userId].saldo += refundAmount;
      if (orders[orderId]) {
        orders[orderId].status = 'canceled';
      }
    }

    res.json({ 
      success: true, 
      message: `Refund Rp ${refundAmount.toLocaleString('id-ID')}`,
      saldoSisa: users[userId].saldo
    });
    
    logAdminAction(userId, 'cancel_order', { orderId, refund: refundAmount });
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal batalkan order" });
  }
});

// 16. FINISH ORDER
app.post('/api/finish/:orderId', async (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }
    
    const { orderId } = req.params;
    
    if (orders[orderId] && orders[orderId].userId !== userId) {
      return res.status(403).json({ success: false, error: "Akses ditolak" });
    }

    await axios.post(
      `${BASE_URL}/orders/finish`,
      { id: parseInt(orderId) },
      { headers: HEADERS }
    );

    if (orders[orderId]) {
      orders[orderId].status = 'completed';
    }

    res.json({ success: true, status: 'completed' });
    
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal selesaikan order" });
  }
});

// 17. GET BALANCE
app.get('/api/balance', (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }

    res.json({ 
      success: true, 
      data: { 
        balance: users[userId].saldo,
        email: users[userId].email
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal cek saldo" });
  }
});

// 18. GET ORDERS
app.get('/api/orders', (req, res) => {
  try {
    const userId = authenticateSession(req);
    if (!userId) {
      return res.status(401).json({ success: false, error: "Tidak terautentikasi" });
    }

    const { limit = 20, offset = 0, status } = req.query;
    
    let userOrders = Object.entries(orders)
      .filter(([_, order]) => order.userId === userId)
      .map(([id, order]) => ({ id, ...order }));
    
    if (status) {
      userOrders = userOrders.filter(o => o.status === status.toLowerCase());
    }
    
    const paginated = userOrders.slice(offset, offset + limit);
    
    res.json({
      success: true,
      data: paginated,
      meta: { total: userOrders.length, limit, offset }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch orders" });
  }
});

// 19. ADMIN DASHBOARD
app.get('/api/admin/dashboard', (req, res) => {
  try {
    const adminKey = req.headers['x-admin-key'];
    if (adminKey !== process.env.ADMIN_KEY) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }
    
    const totalUsers = Object.keys(users).length;
    const totalOrders = Object.keys(orders).length;
    const totalRevenue = Object.values(users).reduce((sum, u) => sum + u.totalSpent, 0);
    const totalSaldo = Object.values(users).reduce((sum, u) => sum + u.saldo, 0);
    
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalOrders,
        totalRevenue,
        totalSaldo,
        recentLogs: Object.values(adminLogs).slice(-10)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: "Gagal fetch dashboard" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
  console.log(`📊 Admin panel: /admin (dengan x-admin-key)`);
});
