# Security Policy

AnonChat is an open-source project provided as-is under the MIT license. It has
**not** undergone a third-party security audit. Please read the
[threat model](docs/THREAT_MODEL.md) to understand what AnonChat does and does
not protect against — in particular, that the SPAKE2 layer is a custom
implementation and that a malicious server could serve backdoored client code.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Open a [GitHub Security Advisory](https://github.com/jakub2929/E2EAnon/security/advisories/new)
  on the repository, or
- contact the maintainer through the channel listed on the repository profile.

Include: a description, affected component (server relay, SPAKE2/handshake,
key distribution, deployment), reproduction steps, and impact. We aim to
acknowledge reports within a reasonable time for a volunteer project.

## Scope

In scope: anything that breaks the documented guarantees — e.g. the server being
able to read message content or derive keys, a non-member reading messages, a
break in the SPAKE2/handshake/rotation logic, or invite single-use/expiry/rate
limiting being bypassable.

Out of scope (by design — see the [threat model](docs/THREAT_MODEL.md)):
malicious members, compromised endpoints, traffic analysis/metadata, denial of
service, and a server that serves malicious client code.
