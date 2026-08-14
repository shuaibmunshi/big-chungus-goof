/** INTENTIONALLY VULNERABLE: ReDoS (CWE-1333) and unsafe deserialization (CWE-502). */
'use strict';

const validator = require('validator');

// Nested quantifiers: catastrophic backtracking on long non-matching input.
const EMAIL_RE = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
const TAG_RE = /^(\s*\w+\s*)+$/;

function isEmail(input) {
  return EMAIL_RE.test(input);
}

function parseTags(input) {
  return TAG_RE.test(input) ? input.trim().split(/\s+/) : [];
}

// Regex built from user input.
function matchesFilter(value, filter) {
  return new RegExp(filter).test(value);
}

// validator 5.x is long unmaintained; also coerces non-strings.
function isUrl(input) {
  return validator.isURL(String(input));
}

// Untrusted JSON merged into a nested object without a __proto__ guard.
function applyPatch(target, patch) {
  Object.keys(patch).forEach((key) => {
    if (typeof patch[key] === 'object' && patch[key] !== null) {
      target[key] = target[key] || {};
      applyPatch(target[key], patch[key]);
    } else {
      target[key] = patch[key];
    }
  });
  return target;
}

// Mongo-style query passed straight through, so {"$ne": null} works.
function buildQuery(req) {
  return { username: req.body.username, password: req.body.password };
}

module.exports = { isEmail, parseTags, matchesFilter, isUrl, applyPatch, buildQuery };
