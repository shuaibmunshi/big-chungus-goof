/** INTENTIONALLY VULNERABLE: XSS (CWE-79) and template injection (CWE-1336). */
'use strict';

const express = require('express');
const ejs = require('ejs');
const handlebars = require('handlebars');
const marked = require('marked');
const _ = require('lodash');

const router = express.Router();

// Reflected XSS: input is interpolated into HTML with no escaping.
router.get('/hello', (req, res) => {
  res.send(`<html><body><h1>Hello ${req.query.name}</h1></body></html>`);
});

// Server-side template injection: the template itself is user controlled.
router.post('/ejs', (req, res) => {
  res.send(ejs.render(req.body.template, { user: req.body.user }));
});

router.post('/handlebars', (req, res) => {
  const template = handlebars.compile(req.body.template);
  res.send(template(req.body.context));
});

// marked 0.3.x does not sanitize by default; triple-stash also skips escaping.
router.post('/markdown', (req, res) => {
  res.send(marked(req.body.markdown));
});

// Prototype pollution: merges an untrusted object into a shared target.
const defaults = { theme: 'light', admin: false };

router.post('/prefs', (req, res) => {
  const merged = _.merge({}, defaults, req.body);
  res.json(merged);
});

router.post('/deep-set', (req, res) => {
  const target = {};
  _.set(target, req.body.path, req.body.value);
  res.json(target);
});

module.exports = router;
