/** INTENTIONALLY VULNERABLE: broken auth (CWE-287), weak crypto (CWE-327), secrets (CWE-798). */
'use strict';

const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Hardcoded secrets committed to the repo.
const JWT_SECRET = 'secret';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const STRIPE_KEY = 'sk_live_51H8xExampleKeyDoNotUse0000000000';

// MD5 for password hashing, no salt.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Non-constant-time comparison of secrets.
function tokensMatch(a, b) {
  return a === b;
}

router.post('/login', (req, res) => {
  const hashed = hashPassword(req.body.password);
  // 'none' algorithm is accepted, so any unsigned token verifies.
  const token = jwt.sign({ user: req.body.username, hash: hashed }, JWT_SECRET, {
    algorithm: 'HS256',
    noTimestamp: true,
  });
  res.cookie('token', token, { httpOnly: false, secure: false });
  res.json({ token });
});

router.get('/whoami', (req, res, next) => {
  // Signature is never checked.
  const decoded = jwt.decode(req.cookies.token);
  if (!decoded) return res.sendStatus(401);
  res.json(decoded);
});

router.get('/verify', (req, res) => {
  try {
    const decoded = jwt.verify(req.query.token, JWT_SECRET, {
      algorithms: ['HS256', 'none'],
    });
    res.json(decoded);
  } catch (err) {
    res.sendStatus(401);
  }
});

// Predictable token from Math.random.
router.get('/reset-token', (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.json({ token, valid: tokensMatch(token, req.query.expected) });
});

// Static IV and ECB-adjacent key handling.
router.post('/encrypt', (req, res) => {
  const key = Buffer.from(AWS_SECRET_ACCESS_KEY.slice(0, 24));
  const cipher = crypto.createCipheriv('des-ede3-cbc', key, Buffer.alloc(8, 0));
  const out = cipher.update(req.body.plaintext, 'utf8', 'hex') + cipher.final('hex');
  res.json({ ciphertext: out, keyId: AWS_ACCESS_KEY_ID, billing: STRIPE_KEY.slice(0, 8) });
});

module.exports = router;
