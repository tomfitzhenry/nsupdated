# nsupdated

A stateless proxy that exposes any [DNSControl](https://dnscontrol.org/) v5
DNS provider as RFC 2136 dynamic updates and AXFR over a Unix domain socket.

Many DNS providers only offer an HTTP API. `nsupdated` abstracts that away,
translating:

- **RFC 2136 UPDATE** messages into provider API calls via DNSControl's
  provider library;
- **AXFR** (RFC 5936) transfers of the zone.

It performs no authentication of its own: terminate mTLS in front of the
socket, for example with [ghostunnel](https://github.com/ghostunnel/ghostunnel).

## Usage

The provider is configured with a DNSControl [`creds.json`](https://dnscontrol.org/js/creds/):

```json
{
  "mythicbeasts": {
    "TYPE": "MYTHICBEASTS",
    "keyID": "...",
    "secret": "$MYTHICBEASTS_SECRET"
  }
}
```

```
nsupdated \
  -listen /run/nsupdated.sock \
  -creds-file /etc/nsupdated/creds.json \
  -creds-name mythicbeasts \
  -log-level info
```

- `-listen`: the Unix domain socket to listen on. A stale socket from a
  previous run is removed on startup and on shutdown.
- `-creds-file`: path to a DNSControl `creds.json`.
- `-creds-name`: the name of the provider entry within `creds.json`.
- `-log-level`: one of `debug`, `info`, `warn`, `error`. Requests are logged
  at `debug`.

The zone to operate on comes from the client's message; there is no zone
whitelist. A single provider instance is created at startup and shared across
requests; the provider itself handles its login and bearer token.

Any DNSControl provider that can read a whole zone (`get-zones`-style) works:
for example `MYTHICBEASTS`, `CLOUDFLARE`, or `POWERDNS`. Only the providers
imported into `internal/provider/provider.go` are available; add more there
if you need them.

### Clients

Point an RFC 2136 client at the socket over mTLS. For example with
[Knot](https://www.knot-dns.cz/), using [nsdiff](https://github.com/miekg/nsdiff)
against a live DNS view, or with `nsupdate`:

```
server 127.0.0.1 port 853
update add www.example.com. 300 A 1.2.3.4
send
```

`nsupdated` answers plain SOA queries with a synthesized SOA, so clients that
probe for the SOA before transferring work too.

## Design

- Stateless: every request reads the zone from the provider; nothing is cached
  (except the provider's own in-memory token handling).
- An update is evaluated against a fetched copy of the zone and committed as
  the difference. RRsets that only grew are appended; RRsets that were emptied
  are deleted; any other change atomically replaces the RRset, because most
  provider APIs delete by name and type only. Each update is a whole-zone
  read-modify-write cycle, so updates to the same zone are serialized.
- Prerequisites map to the RFC 2136 response codes: `NXRRSET` for RRset
  prerequisites, `NXDOMAIN` for name prerequisites, `NOTZONE` for names outside
  the zone, `FORMERR` for malformed sections.
- AXFR synthesizes the opening and closing SOA records, since DNS provider
  APIs generally never expose SOA.

## Development

```
nix develop
go test ./...
```

`nix flake check` fetches the Go dependencies through `buildGoModule`'s
`vendorHash`, so no `vendor/` directory is kept in the repo.

## Testing

- Unit tests for the RFC 2136 handler (`internal/rfc2136`) and the DNSControl
  provider adapter (`internal/provider`).
- An integration test (`integration_test.go`) drives the full stack over a real
  Unix socket: an in-memory DNSControl provider and the real `dns.Server`,
  exercising adds, deletes, prerequisites, error codes, TTLs, TXT escaping,
  and AXFR.
- A NixOS VM test (`vm-tests/axfrddns.nix`, part of `nix flake check`)
  exercises the whole deployment over `nsupdate(1)` and a live Knot DNS
  primary: adds, deletes, RRset replacements, and prerequisite successes and
  failures (`NXDOMAIN`, `NXRRSET`), with `dig` verifying both knotd and an
  AXFR through nsupdated.
