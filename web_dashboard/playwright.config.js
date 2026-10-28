const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: './tests', timeout: 90000, workers: 1,
  outputDir: '../output/browser-tests',
  use: { baseURL: 'http://localhost:3001', channel: 'chrome', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: { command: 'node server.js', url: 'http://localhost:3001/api/health', reuseExistingServer: true, timeout: 20000 }
});
