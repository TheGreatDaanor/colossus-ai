# SSRF collaborator: deploy runbook

The collaborator is the listener that targets call back to when they are vulnerable to SSRF. Each Colossus deployment runs one, on a host of its own, as its own process (`npm run collaborator`, code in `src/collaborator/`). Until it is set up, active scans still run but report SSRF as **not tested** (`unavailable`, reason `collaborator-not-configured`).

## What you need

- A zone you control for callbacks, e.g. `oast.example.net`. Use a dedicated subdomain, never a zone that serves anything else.
- A host with a static public IPv4 address that can bind UDP 53 and TCP 80. Call that address `LISTENER_IP` below.
- A private network path from the Colossus host to the listener's query API (TCP 8443 by default).

## 1. Delegate the zone

At the DNS provider for the parent zone (`example.net`), add:

```
ns1.oast.example.net.   A    <LISTENER_IP>
oast.example.net.       NS   ns1.oast.example.net.
```

The listener answers every name under `oast.example.net` with `LISTENER_IP` (TTL 0), so a target that resolves a token also reaches the HTTP listener.

Check it from any machine:

```
dig +short anything.oast.example.net      # prints LISTENER_IP
```

## 2. Generate the shared secret

```
openssl rand -hex 32
```

Store it in your secret manager. The same value goes to the listener and to Colossus.

## 3. Run the listener

On the listener host:

| Variable | Value |
|---|---|
| `COLLABORATOR_BASE_DOMAIN` | `oast.example.net` |
| `COLLABORATOR_PUBLIC_IP` | `LISTENER_IP` |
| `COLLABORATOR_SECRET` | the secret from step 2 |
| `COLLABORATOR_QUERY_HOST` | the **private** interface address. Default `127.0.0.1`; never `0.0.0.0` on a public interface |
| `COLLABORATOR_QUERY_PORT` | default `8443` |
| `COLLABORATOR_DNS_PORT` / `COLLABORATOR_HTTP_PORT` | default `53` / `80` |

```
npm run collaborator
```

Binding ports 53 and 80 needs root or `CAP_NET_BIND_SERVICE`. Run it under a supervisor (systemd or a container restart policy). Hits are held in memory for about 10 minutes. A restart only loses callbacks for scans that are draining at that moment, and those come back as `unavailable`, not as clean.

The listener only keeps hits for tokens that Colossus signed with the shared secret, so internet noise under the zone cannot push real callbacks out of the buffer. A hand-made name like `x.oast.example.net` still gets a DNS answer and an HTTP `ok`, but it is never stored or returned by the query API.

The listener also refuses names outside its zone (`REFUSED`) and ignores DNS responses. `COLLABORATOR_PUBLIC_IP` must be a dotted-quad IPv4 address, or the listener exits at startup.

Firewall: open UDP 53 and TCP 80 to the internet. Open the query port to the Colossus host only.

## 4. Point Colossus at it

On the Colossus host, set all three, then restart:

| Variable | Value |
|---|---|
| `COLLABORATOR_BASE_DOMAIN` | `oast.example.net` |
| `COLLABORATOR_QUERY_URL` | `http://<listener private address>:8443/hits` |
| `COLLABORATOR_SECRET` | the secret from step 2 |

If only some are set, Colossus logs `SSRF collaborator disabled: … not set` and treats the collaborator as absent.

## 5. Verify end to end

Every active scan first runs a self-test: Colossus fetches a fresh token URL itself and waits for the listener to report it. If that fails, the scan's SSRF attempts read `unavailable` with reason `collaborator-self-test-failed: …`, which names the broken piece:

- `query api: collaborator query api answered 401`: the secrets differ.
- `query api: fetch failed`: Colossus cannot reach the query port.
- `no http callback for the self-test token …`: delegation or the HTTP listener is broken. Re-run the `dig` from step 1 and `curl -H 'Host: x.oast.example.net' http://LISTENER_IP/`.

Then run an active scan against a target you are authorized to test whose query parameter fetches the given URL server-side. Expect a `high` `ssrf` finding with `protocols` and `callerSourceIp` in its `structuredEvidence`.

## Rotating the secret

Rotation is manual. Generate a new secret, set it on the listener, restart it, then set it on Colossus and restart that. Scans that start between the two restarts report SSRF `unavailable` (the self-test gets a 401), so rotate during a quiet window.
