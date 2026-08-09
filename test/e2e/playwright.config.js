const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: 'saml-login.spec.js',
  timeout: 30000,
  use: {
    headless: true,
    trace: 'retain-on-failure'
  }
});
