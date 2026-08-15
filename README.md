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

Adjust the exact commands to match what's actually in `package.json` — I'm inferring from the project conventions I have visibility into (the CLAUDE.md commands: `npx vitest run`, `npx tsc --noEmit`, `npx eslint`, `npm run dev`), but I haven't read the current README or package.json in this response so I can't confirm there isn't more project-specific setup (env vars, DB setup, etc.) that should go in there too.
