# Repository-derived Context

This context is attached to model requests together with the ecosystems selected
for this job. Establish frameworks and services from evidence in the current
checkout. Establish effective deployment settings from evidence for this project's environment.

## Product Boundary

An operator may confirm a deployment profile for a particular project. Apply only
the supplied profile's declared facts and component rules, including their conditions
and exceptions. When citing a platform-policy exclusion, identify the affected path
and its owner where specified. An exclusion for incoming TLS does not cover outbound
HTTPS. Without a confirmed profile, investigate each component on the available
evidence and leave unresolved deployment conditions open.

`docker-compose` and Compose files can describe either a developer machine or a
real deployment. Classify them from the current job's deployment contract and
build evidence, never from the filename alone.

## Test And Non-Production Paths

The conventions below identify likely test code. They lower reachability
confidence but do not override a production import, a shipped artifact, or a
real credential. A dependency imported only from these paths is test-only only
when the production build and loading checks agree.

This list is also read by the agent's own code — dependency search, CodeQL
import gate, condition search and SAST heuristics use these patterns. Edit them
here, and only here. A pattern ending in `/` is a directory name matched against
any segment of a path; any other pattern is a file-name glob. Language-specific
patterns live in the ecosystem files.

Only conventions the whole language or its standard test runner uses belong
here. Every pattern added makes more code count as test code and must not be
based on a directory name used by one project.

Directories, any ecosystem:

- `test/`
- `tests/`
- `testing/`
- `spec/`
- `specs/`
- `fixture/`
- `fixtures/`
- `mocks/`
- `e2e/`
- `features/`

File names, any ecosystem:

- `*.feature`

## Triage Rules

- Dependency presence alone is insufficient: check affected version, actual use,
  call reachability, and every advisory precondition.
- A govulncheck or Wolfee closure is strong evidence, but its blind spots include
  reflection, callbacks, interface dispatch, generated code, plugins, and build
  constraints. An unsuccessful audit leaves a proposed closure for a person.
- A reachable call is not automatically exploitable. Check attacker-controlled
  input and the required deployment conditions.
- OSV, EPSS, and CISA KEV are supporting evidence. A timeout is missing evidence,
  never evidence that a vulnerability is absent.
- A negative search establishes absence only when its result explicitly says the
  search was complete for the relevant repository scope. File limits, excluded
  runtime configuration, generated code, and unreadable files make it incomplete.
- An opt-in feature is on when current repository code or effective operator
  configuration enables it. Do not infer either enabled or disabled from a
  package merely being installed or from a partial search miss.
- Environment variables and service configuration are not inherently attacker
  controlled or inherently trusted. Identify who can set them in this job's
  threat model, including MR/CI input, request-derived configuration, and
  deployment operators.
- Responses from another service can carry attacker-controlled data even when
  the service address is configured by an operator. Check redirects, stored
  content, user-controlled records, compromised upstreams, and request-selected
  addresses before treating a client-side flaw as unreachable.
- When a condition has several required parts, one completely checked absent
  part is enough to reject exploitability. If that part is unknown, the whole
  condition remains unproven rather than absent.
- Frameworks call registered event listeners, subscribers, handlers, console
  commands, template filters and services without a direct project call site.
  Decide from active production registration, not from call-graph absence.
