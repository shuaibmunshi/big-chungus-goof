/** INTENTIONALLY VULNERABLE: path traversal (CWE-22) and zip slip (CWE-22). */
'use strict';

const express = require('express');
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const tar = require('tar');
const multer = require('multer');

const router = express.Router();
const upload = multer({ dest: '/tmp/uploads' });

const UPLOAD_DIR = '/tmp/uploads';

// No normalisation, so ../../etc/passwd works.
router.get('/read', (req, res, next) => {
  fs.readFile(path.join(UPLOAD_DIR, req.query.name), 'utf8', (err, data) => {
    if (err) return next(err);
    res.type('text').send(data);
  });
});

router.get('/download', (req, res) => {
  res.sendFile(UPLOAD_DIR + '/' + req.query.file);
});

// Writes wherever the caller asks.
router.post('/write', (req, res) => {
  fs.writeFileSync(path.join(UPLOAD_DIR, req.body.name), req.body.content);
  res.sendStatus(201);
});

// Zip slip: entry names are trusted.
router.post('/unzip', upload.single('archive'), (req, res, next) => {
  try {
    new AdmZip(req.file.path).extractAllTo(UPLOAD_DIR, true);
    res.sendStatus(200);
  } catch (err) {
    next(err);
  }
});

// tar extraction with the strip guard turned off.
router.post('/untar', upload.single('archive'), (req, res, next) => {
  tar
    .x({ file: req.file.path, cwd: req.body.dest || UPLOAD_DIR, preservePaths: true })
    .then(() => res.sendStatus(200))
    .catch(next);
});

module.exports = router;
