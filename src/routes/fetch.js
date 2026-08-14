/** INTENTIONALLY VULNERABLE: SSRF (CWE-918), open redirect (CWE-601), XXE (CWE-611). */
'use strict';

const express = require('express');
const https = require('https');
const axios = require('axios');
const fetch = require('node-fetch');
const request = require('request');
const { DOMParser } = require('xmldom');

const router = express.Router();

// Whole URL comes from the caller, so internal hosts are reachable.
router.get('/proxy', async (req, res, next) => {
  try {
    const upstream = await axios.get(req.query.url);
    res.send(upstream.data);
  } catch (err) {
    next(err);
  }
});

router.post('/webhook', async (req, res, next) => {
  try {
    const upstream = await fetch(req.body.callbackUrl, {
      method: 'POST',
      body: JSON.stringify(req.body.payload),
      headers: { 'Content-Type': 'application/json' },
      // Certificate validation disabled.
      agent: new https.Agent({ rejectUnauthorized: false }),
    });
    res.json({ status: upstream.status });
  } catch (err) {
    next(err);
  }
});

// Only the prefix is checked, so https://internal.example.com.attacker.tld passes.
router.get('/avatar', (req, res, next) => {
  const url = req.query.src;
  if (url.indexOf('https://cdn.example.com') !== 0 && !url.startsWith('http')) {
    return res.sendStatus(400);
  }
  request({ url, strictSSL: false }).on('error', next).pipe(res);
});

// Open redirect.
router.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

// XXE: external entities are resolved by the parser.
router.post('/xml', (req, res) => {
  const doc = new DOMParser().parseFromString(req.body.xml, 'text/xml');
  res.type('text').send(doc.documentElement.textContent);
});

module.exports = router;
