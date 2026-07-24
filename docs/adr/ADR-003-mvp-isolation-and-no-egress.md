# ADR-003: MVP Isolation and No-Egress Strategy

- **Status:** Accepted
- **Date:** 2026-07-24
- **Decision owners:** Project owner

## Context

The first Vertical Slice must show an agent attempting to send a fake canary after reading a fake secret. Opening a real network connection would introduce DNS, routing, CI, Docker-network, and accidental-egress risks that are unnecessary for validating the attack-to-incident pipeline.

The MVP also needs to demonstrate file access without exposing the host filesystem.

## Decision

Use in-process capability isolation for the deterministic MVP:

- The fake-file adapter exposes only explicitly seeded virtual resources
- It never passes arbitrary agent paths to general host-filesystem APIs
- `http_post` is implemented by `LabHttpSinkAdapter`
- The only valid destination is the exact identifier `lab://exfiltration-sink`
- The adapter records the proposed payload in memory or approved local MVP storage
- It opens no operating-system network socket and performs no DNS resolution
- Unknown tools, invalid schemas, host paths, traversal paths, external destinations, and alternate schemes are denied
- Safety validation cannot be disabled by the vulnerable profile
- The MVP launches no shell, subprocess, plugin, or untrusted code

## Rationale

- Eliminates accidental external egress by construction
- Removes Docker and network dependencies from the first implementation
- Keeps tests deterministic and CI-friendly
- Separates proof of the security pipeline from proof of real network telemetry
- Makes “vulnerable agent behavior” compatible with safe developer-machine boundaries

## Consequences

### Positive

- No DNS or routing ambiguity
- No external target can be reached through the supported adapters
- Simple positive and negative tests
- Fast local and CI execution

### Negative

- The MVP does not validate operating-system network telemetry
- The sink event is simulated evidence, not a packet or proxy observation
- In-process isolation cannot safely support arbitrary execution

## Alternatives Considered

- **Local HTTP server on loopback:** Still opens a socket and introduces port, resolver, and CI behavior
- **Docker network with controlled proxy:** Valuable for later network-telemetry testing but unnecessary for the MVP
- **Mocking a general HTTP client:** A missed code path could still open a real socket; a dedicated non-network adapter is safer
- **External test endpoint:** Rejected because it violates the lab safety boundary

## Verification

- Test that `lab://exfiltration-sink` is accepted
- Test that HTTP, HTTPS, IP, hostname, protocol-relative, and malformed destinations are denied
- Guard or instrument socket creation in tests and assert that no socket opens
- Test that only the seeded fake path is readable
- Test absolute, traversal, host, symlink-like, and unknown paths
- Test unknown tools and invalid schema fields
- Scan reports for the raw canary value

## Supersession Trigger

Any requirement for real network telemetry, a controlled proxy, Docker networking, shell execution, or third-party tool code requires a new ADR and an updated threat model. It must not silently modify this MVP boundary.

