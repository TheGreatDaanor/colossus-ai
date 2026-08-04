import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Tests live beside the code they test.
    include: ['src/**/*.test.ts'],
    environment: 'node',
    // No watch here. `npm test` must terminate — an unattended agent loop that
    // invokes a watching test runner hangs until its wall-clock cap.
    watch: false,
  },
});
