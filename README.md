# ai-vuln-scanner

```markdown
## How to use

### Prerequisites
- Node.js (see `.nvmrc` or `package.json` engines field if present)
- npm

### Setup
\`\`\`bash
npm install
\`\`\`

### Development
\`\`\`bash
npm run dev
\`\`\`

### Testing
\`\`\`bash
npx vitest run
\`\`\`

Run a single test file:
\`\`\`bash
npx vitest run src/services/scanner.test.ts
\`\`\`

### Typecheck & lint
\`\`\`bash
npx tsc --noEmit
npx eslint
\`\`\`
```

Adjust the exact commands to match what's actually in `package.json` (the CLAUDE.md commands: `npx vitest run`, `npx tsc --noEmit`, `npx eslint`, `npm run dev`)
