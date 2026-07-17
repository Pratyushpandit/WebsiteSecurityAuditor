const express = require('express');
const path = require('path');
const scanRoutes = require('./routes/scan');
const { ALLOWED_DOMAINS } = require('./config/allowlist');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/api', scanRoutes);

app.listen(PORT, () => {
  console.log(`Website Security Auditor running at http://localhost:${PORT}`);
  console.log(`Authorized domains (${ALLOWED_DOMAINS.length}):`, ALLOWED_DOMAINS.length ? ALLOWED_DOMAINS : '(none configured yet - edit server/config/allowlist.js)');
});
