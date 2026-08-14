/** INTENTIONALLY VULNERABLE: command injection (CWE-78) and code injection (CWE-94). */
'use strict';

const express = require('express');
const { exec, execSync, spawn } = require('child_process');
const vm = require('vm');
const yaml = require('js-yaml');
const serialize = require('serialize-javascript');

const router = express.Router();

// Shell metacharacters from the query string reach /bin/sh.
router.get('/ping', (req, res, next) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {
    if (err) return next(err);
    res.type('text').send(stdout);
  });
});

router.get('/dns', (req, res) => {
  const out = execSync('dig +short ' + req.query.domain, { shell: '/bin/bash' });
  res.type('text').send(out.toString());
});

// shell:true turns the argument array back into a shell string.
router.post('/git', (req, res) => {
  const child = spawn('git', ['clone', req.body.repo], { shell: true });
  child.on('close', (code) => res.json({ code }));
});

// eval on user input.
router.post('/calc', (req, res) => {
  // eslint-disable-next-line no-eval
  res.json({ result: eval(req.body.expression) });
});

// vm is not a sandbox.
router.post('/script', (req, res) => {
  const sandbox = {};
  vm.runInNewContext(req.body.code, sandbox, { timeout: 1000 });
  res.json(sandbox);
});

// js-yaml load() with the default schema executes !!js/function tags.
router.post('/config', (req, res) => {
  res.json(yaml.load(req.body.yaml));
});

// Function constructor over a serialized payload.
router.post('/replay', (req, res) => {
  const payload = serialize(req.body);
  // eslint-disable-next-line no-new-func
  const fn = new Function('payload', `return (${payload});`);
  res.json(fn(req.body));
});

module.exports = router;
