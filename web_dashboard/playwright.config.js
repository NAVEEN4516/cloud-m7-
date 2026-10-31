const { defineConfig } = require('@playwright/test');
const port = process.env.CLOUD_M7_TEST_PORT || '3001';
module.exports = defineConfig({
  testDir: './tests', timeout: 90000, workers: 1,
  outputDir: '../output/browser-tests',
  use: { baseURL: `http://localhost:${port}`, channel: 'chrome', viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
  webServer: { command: 'node server.js', env: { PORT: port }, url: `http://localhost:${port}/api/health`, reuseExistingServer: !process.env.CLOUD_M7_TEST_PORT, timeout: 20000 }
});
