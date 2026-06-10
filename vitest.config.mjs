import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // DOMPurify needs a DOM; jsdom provides the global window it binds to.
    environment: 'jsdom',
  },
});
