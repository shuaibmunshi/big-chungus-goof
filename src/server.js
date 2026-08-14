/**
 * INTENTIONALLY VULNERABLE. Test fixture for static and dependency analysis.
 * Do not deploy this. Do not copy these patterns.
 */
'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const app = express();

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

app.use('/sql', require('./routes/sql'));
app.use('/exec', require('./routes/exec'));
app.use('/files', require('./routes/files'));
app.use('/render', require('./routes/render'));
app.use('/auth', require('./routes/auth'));
app.use('/fetch', require('./routes/fetch'));

// Full stack traces returned to the client.
app.use((err, req, res, next) => {
  res.status(500).send(`<pre>${err.stack}</pre>`);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`listening on ${PORT}`));

module.exports = app;
