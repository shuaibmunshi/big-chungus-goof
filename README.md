# big-chungus-goof

Test fixture for generating variable sized vulnerable packages.
**Intentionally vulnerable. Do not deploy. Do not publish.**

## What is in here

| Item | Detail |
| --- | --- |
| `package.json` | 1.21 MB, generated. 47 pinned vulnerable dependencies, 4 dev dependencies. |
| `package-lock.json` | lockfile v3, 441 resolved packages. |
| `scripts/generate-package-json.js` | Regenerates the manifest. Bloat lives in `keywords`, `contributors`, and `fixture`. npm ignores those fields. |
| `src/` | Vulnerable Express app for static analysis. |

## Vulnerability classes in `src/`

| File | Classes |
| --- | --- |
| `src/routes/sql.js` | SQL injection (CWE-89), hardcoded DB credentials (CWE-798) |
| `src/routes/exec.js` | Command injection (CWE-78), `eval` / `vm` / `js-yaml` code injection (CWE-94) |
| `src/routes/files.js` | Path traversal, zip slip, tar slip (CWE-22) |
| `src/routes/render.js` | XSS (CWE-79), template injection (CWE-1336), prototype pollution (CWE-1321) |
| `src/routes/auth.js` | MD5 password hashing (CWE-327), `alg:none` JWT, hardcoded AWS/Stripe keys (CWE-798) |
| `src/routes/fetch.js` | SSRF (CWE-918), open redirect (CWE-601), XXE (CWE-611), TLS verification off (CWE-295) |
| `src/lib/validate.js` | ReDoS (CWE-1333), unsafe merge (CWE-1321), NoSQL operator injection |
| `src/server.js` | Stack traces returned to the client (CWE-209) |

The AWS and Stripe keys in `src/routes/auth.js` are the public AWS documentation
example key and a fake `sk_live_` string. Neither is a real credential.

## Run the scans

1. `npm install --ignore-scripts --legacy-peer-deps` — restores `node_modules`.
2. `npm audit` — dependency scan, reads the 1 MB manifest and the lockfile.
3. Run your static analyzer against `src/`.

## Change the manifest size

`node scripts/generate-package-json.js 3000000` writes a 3 MB manifest.
The filler is deterministic, so a regeneration at the same target gives the same file.
Run `npm install` again after you change the dependency list.
