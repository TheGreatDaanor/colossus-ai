import { createSocket } from 'node:dgram';
import { serve } from '@hono/node-server';
import type { HttpBindings } from '@hono/node-server';
import { Hono } from 'hono';
import { buildDnsAnswer, parseDnsQuestion } from './dns.js';
import { HitBuffer, tokenFromHostname } from './hit-buffer.js';
import { createQueryApi } from './query-api.js';

// The standalone SSRF collaborator listener: one per Colossus deployment, run as its
// own process (`npm run collaborator`). Three sockets:
//   - UDP DNS (public): authoritative for the NS-delegated zone; records a `dns` hit
//     per token lookup and answers with this host's public address;
//   - HTTP (public): records an `http` hit per request whose Host carries a token;
//   - the query API (internal only): what Colossus polls, guarded by the secret.
// The socket glue here is deliberately untested (an integration gap, issue 055); the
// logic it calls is covered in listener.test.ts. See docs/collaborator-runbook.md.

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    console.error(`collaborator: ${name} must be set`);
    process.exit(1);
  }
  return value;
}

const baseDomain = required('COLLABORATOR_BASE_DOMAIN');
const publicIp = required('COLLABORATOR_PUBLIC_IP');
const secret = required('COLLABORATOR_SECRET');
const dnsPort = Number(process.env['COLLABORATOR_DNS_PORT'] ?? 53);
const httpPort = Number(process.env['COLLABORATOR_HTTP_PORT'] ?? 80);
const queryHost = process.env['COLLABORATOR_QUERY_HOST'] ?? '127.0.0.1';
const queryPort = Number(process.env['COLLABORATOR_QUERY_PORT'] ?? 8443);

// ~10 min TTL: comfortably past one scan's 30s drain, short enough that a token's
// hits are gone long before anyone could ask about it again.
const buffer = new HitBuffer({ ttlMs: 10 * 60 * 1000, maxHits: 100_000 });

// IPv4 peers arrive as `::ffff:a.b.c.d` on a dual-stack socket.
const plainIp = (address: string | undefined) => (address ?? 'unknown').replace(/^::ffff:/, '');

const dns = createSocket('udp4');
dns.on('message', (packet, remote) => {
  const question = parseDnsQuestion(packet);
  if (question === null) return;
  const token = tokenFromHostname(question.name, baseDomain);
  if (token !== null) buffer.record({ token, protocol: 'dns', callerSourceIp: remote.address });
  dns.send(buildDnsAnswer(packet, question, publicIp), remote.port, remote.address);
});
dns.on('error', (err) => console.error(`collaborator dns: ${err.message}`));
dns.bind(dnsPort, () => console.warn(`collaborator dns listening on udp/${dnsPort} for *.${baseDomain}`));

const callbacks = new Hono<{ Bindings: HttpBindings }>();
callbacks.all('*', (c) => {
  const token = tokenFromHostname(c.req.header('host') ?? '', baseDomain);
  if (token !== null) {
    buffer.record({ token, protocol: 'http', callerSourceIp: plainIp(c.env.incoming.socket.remoteAddress) });
  }
  return c.text('ok');
});
serve({ fetch: callbacks.fetch, port: httpPort }, (info) =>
  console.warn(`collaborator http listening on :${info.port}`),
);

serve({ fetch: createQueryApi(buffer, secret).fetch, hostname: queryHost, port: queryPort }, (info) =>
  console.warn(`collaborator query api listening on ${queryHost}:${info.port}`),
);
