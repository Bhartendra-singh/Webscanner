
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { URL } = require('url');

const app = express();
app.use(express.json());
app.use(cors());

// Helper: check security headers
function checkSecurityHeaders(headers) {
  const requiredHeaders = {
    'content-security-policy': 'high',
    'strict-transport-security': 'high',
    'x-frame-options': 'medium',
    'x-content-type-options': 'medium',
    'referrer-policy': 'low',
    'permissions-policy': 'low',
  };
  const issues = [];

  for (const [header, risk] of Object.entries(requiredHeaders)) {
    if (!headers[header]) {
      issues.push({
        message: `Missing security header: ${header}`,
        risk,
      });
    }
  }

  return issues;
}

// Check for insecure links (http inside page)
function checkInsecureLinks(html, baseUrl) {
  const issues = [];
  // Find all http:// links that are not the base URL's http/https
  const regex = /href=["'](http:\/\/[^"']+)["']/gi;
  let match;
  while ((match = regex.exec(html)) !== null) {
    const link = match[1];
    if (!link.startsWith('https://')) {
      issues.push({
        message: `Page contains insecure link: ${link}`,
        risk: 'medium',
      });
    }
  }
  return issues;
}

// Test reflected XSS
async function testXSS(url) {
  const xssPayload = '<script>alert(1)</script>';
  const issues = [];

  try {
    const testUrl = new URL(url);

    // If there are existing query params, inject payload in each
    if ([...testUrl.searchParams].length > 0) {
      for (const [key] of testUrl.searchParams) {
        testUrl.searchParams.set(key, xssPayload);
        const res = await axios.get(testUrl.toString(), { timeout: 5000 });
        if (res.data && res.data.includes(xssPayload)) {
          issues.push({
            message: `Reflected XSS detected in parameter: ${key}`,
            risk: 'high',
          });
        }
      }
    } else {
      // No params, add one
      testUrl.searchParams.set('xss_test', xssPayload);
      const res = await axios.get(testUrl.toString(), { timeout: 5000 });
      if (res.data && res.data.includes(xssPayload)) {
        issues.push({
          message: 'Reflected XSS vulnerability detected.',
          risk: 'high',
        });
      }
    }
  } catch {
    // ignore errors
  }

  return issues;
}

// Test SQL Injection
async function testSQLi(url) {
  const sqlPayloads = [`'`, `"`, `' OR '1'='1`, `" OR "1"="1`];
  const sqlErrors = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'quoted string not properly terminated',
    'syntax error',
  ];
  const issues = [];

  try {
    const testUrl = new URL(url);

    if ([...testUrl.searchParams].length > 0) {
      for (const [key] of testUrl.searchParams) {
        for (const payload of sqlPayloads) {
          testUrl.searchParams.set(key, payload);
          const res = await axios.get(testUrl.toString(), { timeout: 5000, validateStatus: null });
          const body = res.data.toLowerCase();
          for (const errorMsg of sqlErrors) {
            if (body.includes(errorMsg)) {
              issues.push({
                message: `Possible SQL Injection detected in parameter: ${key} with payload: ${payload}`,
                risk: 'high',
              });
            }
          }
        }
      }
    } else {
      // No params, add one and test
      for (const payload of sqlPayloads) {
        testUrl.searchParams.set('sqli_test', payload);
        const res = await axios.get(testUrl.toString(), { timeout: 5000, validateStatus: null });
        const body = res.data.toLowerCase();
        for (const errorMsg of sqlErrors) {
          if (body.includes(errorMsg)) {
            issues.push({
              message: `Possible SQL Injection detected with payload: ${payload}`,
              risk: 'high',
            });
          }
        }
      }
    }
  } catch {
    // ignore errors
  }

  return issues;
}

app.post('/scan', async (req, res) => {
  const { url, scanType } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required.' });
  }

  let issues = [];

  try {
    const response = await axios.get(url, { timeout: 10000 });
    const headers = {};
    // Normalize headers keys to lowercase for easier checks
    for (const [k, v] of Object.entries(response.headers)) {
      headers[k.toLowerCase()] = v;
    }

    // Check for HTTP vs HTTPS
    if (url.startsWith('http://')) {
      issues.push({ message: 'Using insecure HTTP protocol.', risk: 'high' });
    }

    // Simple domain blacklist example (could be extended)
    const insecureDomains = ['testphp.vulnweb.com']; // example
    const hostname = new URL(url).hostname.toLowerCase();
    if (insecureDomains.includes(hostname)) {
      issues.push({ message: 'Domain is listed as insecure.', risk: 'high' });
    }

    // Check missing security headers
    issues = issues.concat(checkSecurityHeaders(headers));

    // Check insecure links on page
    issues = issues.concat(checkInsecureLinks(response.data, url));

    // Scan type specific scans
    if (scanType === 'full') {
      const xssIssues = await testXSS(url);
      const sqliIssues = await testSQLi(url);
      issues = issues.concat(xssIssues, sqliIssues);
    }

    const status = issues.length === 0 ? 'Safe' : 'Vulnerable';

    res.json({
      url,
      status,
      scanType,
      issues: issues.length ? issues : [{ message: 'No vulnerabilities found.', risk: 'none' }],
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to scan the URL. ' + error.message });
  }
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Security scanner running on http://localhost:${PORT}`);
});