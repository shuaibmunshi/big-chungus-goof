#!/usr/bin/env node
/**
 * Generates a package.json that is intentionally larger than 1 MB.
 *
 * Why: this repo is a test fixture for dependency scanning. We need a
 * manifest that crosses the 1 MB mark so we can check parser / upload limits,
 * while still holding real dependency ranges that resolve to known-vulnerable
 * versions.
 *
 * The bloat lives in fields npm ignores (keywords, contributors, and a custom
 * "fixture" block) so that `npm install` still works normally.
 *
 * Usage: node scripts/generate-package-json.js [targetBytes]
 */

const fs = require('fs');
const path = require('path');

const TARGET_BYTES = Number(process.argv[2] || 1_200_000);
const OUT = path.join(__dirname, '..', 'package.json');

// Pinned to versions with published advisories. Exact pins (no ^) so the
// lockfile cannot silently resolve to a patched release.
const dependencies = {
  'adm-zip': '0.4.7',
  'ansi-regex': '3.0.0',
  async: '2.6.0',
  axios: '0.18.0',
  'body-parser': '1.18.0',
  braces: '2.3.0',
  'cookie-parser': '1.4.3',
  debug: '2.6.8',
  'decode-uri-component': '0.2.0',
  'dot-prop': '4.2.0',
  ejs: '2.5.7',
  express: '4.16.0',
  flat: '4.1.0',
  fresh: '0.5.0',
  'glob-parent': '5.1.0',
  growl: '1.9.2',
  handlebars: '4.0.11',
  hoek: '4.2.0',
  ini: '1.3.5',
  'js-yaml': '3.10.0',
  jsonwebtoken: '8.0.0',
  lodash: '4.17.4',
  marked: '0.3.9',
  minimist: '0.0.8',
  moment: '2.18.1',
  morgan: '1.9.0',
  ms: '0.7.1',
  multer: '1.3.0',
  mysql: '2.15.0',
  netmask: '1.0.6',
  'node-fetch': '2.6.0',
  nodemailer: '4.0.1',
  passport: '0.4.0',
  pg: '7.3.0',
  qs: '6.3.0',
  redis: '2.8.0',
  request: '2.81.0',
  'sanitize-html': '1.19.0',
  'serialize-javascript': '1.4.0',
  'shell-quote': '1.6.1',
  tar: '4.4.0',
  'tough-cookie': '2.3.3',
  underscore: '1.12.0',
  validator: '5.7.0',
  ws: '3.3.1',
  xmldom: '0.1.27',
  'yargs-parser': '13.1.1',
};

const devDependencies = {
  'uglify-js': '2.4.24',
  mocha: '5.2.0',
  chai: '4.1.2',
  nyc: '13.0.0',
};

const pkg = {
  name: 'big-chungus-goof',
  version: '1.0.0',
  private: true,
  description:
    'Intentionally vulnerable Node.js fixture with an oversized (>1MB) package.json, used to test dependency and static-analysis scanning. Do not deploy.',
  license: 'UNLICENSED',
  main: 'src/server.js',
  engines: { node: '>=14' },
  scripts: {
    start: 'node src/server.js',
    test: 'mocha --exit',
    'gen:manifest': 'node scripts/generate-package-json.js',
  },
  dependencies,
  devDependencies,
  keywords: [],
  contributors: [],
  fixture: {
    purpose: 'oversized-manifest-test',
    targetBytes: TARGET_BYTES,
    note: 'The arrays below are filler. They exist only to grow this file past 1 MB.',
    filler: [],
  },
};

// Deterministic filler. No randomness, so regenerating gives a stable diff.
const WORDS = [
  'chungus', 'goof', 'bloat', 'manifest', 'fixture', 'payload', 'legacy',
  'monolith', 'shim', 'polyfill', 'vendor', 'bundle', 'transitive', 'advisory',
];

function word(i) {
  return `${WORDS[i % WORDS.length]}-${i.toString(36)}`;
}

let i = 0;
function grow() {
  pkg.keywords.push(`fixture-${word(i)}`);
  pkg.contributors.push({
    name: `Fixture Bot ${i}`,
    email: `fixture-bot-${i}@example.invalid`,
    url: `https://example.invalid/contributors/${word(i)}`,
  });
  pkg.fixture.filler.push({
    id: `filler-${i}`,
    slug: word(i),
    tags: [word(i + 1), word(i + 2), word(i + 3)],
    description: `Filler record ${i} used to inflate the manifest to ${TARGET_BYTES} bytes.`,
  });
  i += 1;
}

let json = '';
do {
  for (let n = 0; n < 250; n += 1) grow();
  json = JSON.stringify(pkg, null, 2) + '\n';
} while (Buffer.byteLength(json, 'utf8') < TARGET_BYTES);

fs.writeFileSync(OUT, json, 'utf8');

const bytes = Buffer.byteLength(json, 'utf8');
console.log(
  `Wrote ${OUT}\n  bytes: ${bytes} (${(bytes / 1024 / 1024).toFixed(2)} MB)` +
    `\n  filler records: ${i}\n  dependencies: ${Object.keys(dependencies).length}` +
    `\n  devDependencies: ${Object.keys(devDependencies).length}`
);
