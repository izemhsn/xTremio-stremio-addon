import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['test/**/*.test.js'],
        // The test files are CommonJS, and Vitest cannot be loaded with
        // require(), so `test`, `expect` and the hooks are provided as globals
        // instead of imported.
        globals: true,
        // One process per test file. Many files set process.env before
        // requiring the app, and the app reads its settings at load time, so
        // files must not share a process (or its module cache).
        pool: 'forks',
        // Some tests start real servers and child processes, or wait out
        // deliberate upstream timeouts, which takes longer than Vitest's
        // 5-second default.
        testTimeout: 30000,
        hookTimeout: 30000
    }
});
