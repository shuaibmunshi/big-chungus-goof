/** INTENTIONALLY VULNERABLE: SQL injection (CWE-89). */
'use strict';

const express = require('express');
const mysql = require('mysql');
const { Client } = require('pg');

const router = express.Router();

const mysqlPool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'hunter2', // hardcoded credential (CWE-798)
  database: 'chungus',
});

// String concatenation straight from the query string into SQL.
router.get('/user', (req, res, next) => {
  const query = `SELECT id, email, ssn FROM users WHERE name = '${req.query.name}'`;
  mysqlPool.query(query, (err, rows) => {
    if (err) return next(err);
    res.json(rows);
  });
});

// Template literal with a body field, plus an ORDER BY that cannot be parameterised.
router.post('/search', async (req, res, next) => {
  const pg = new Client({ connectionString: 'postgres://admin:admin@localhost:5432/chungus' });
  try {
    await pg.connect();
    const sql =
      'SELECT * FROM orders WHERE customer = ' +
      "'" + req.body.customer + "'" +
      ' ORDER BY ' + req.body.sort;
    const result = await pg.query(sql);
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// Second-order injection: value read from a cookie.
router.get('/me', (req, res, next) => {
  mysqlPool.query(`DELETE FROM sessions WHERE token = "${req.cookies.token}"`, (err) => {
    if (err) return next(err);
    res.sendStatus(204);
  });
});

module.exports = router;
